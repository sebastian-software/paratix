import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote, validateMode } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { isSymlink } from "./remoteFileChecks.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

export type FileOwnership = {
  group: string
  mode: string
  owner: string
}

const DEFAULT_FILE_WRITE_MODE = "0644"

export function assertValidChownOwnershipSpec(ownerSpec: string): void {
  if (ownerSpec === "") {
    throw new Error("chown ownership spec must not be empty")
  }

  const [owner = "", group = ""] = ownerSpec.split(":", 2)
  if (owner === "" && group === "") {
    throw new Error("chown ownership spec must include an owner or group")
  }

  for (const [field, value] of [
    ["owner", owner],
    ["group", group],
  ] as const) {
    if (value.startsWith("-")) {
      throw new Error(`chown ${field} component must not start with "-": ${JSON.stringify(value)}`)
    }
  }
}

export function renderChownCommand(ownerSpec: string, remotePath: string): string {
  assertValidChownOwnershipSpec(ownerSpec)
  return `chown -- ${shellQuote(ownerSpec)} ${shellQuote(remotePath)}`
}

export function renderChownSymlinkCommand(ownerSpec: string, remotePath: string): string {
  assertValidChownOwnershipSpec(ownerSpec)
  return `chown -h -- ${shellQuote(ownerSpec)} ${shellQuote(remotePath)}`
}

function renderGuardedMetadataCommand(
  kind: "chmod" | "chown",
  remotePath: string,
  value: string
): string {
  if (kind === "chown") assertValidChownOwnershipSpec(value)

  const operation =
    kind === "chmod"
      ? `chmod -- ${shellQuote(value)} "$path"`
      : `chown -- ${shellQuote(value)} "$path"`

  return [
    `path=${shellQuote(remotePath)}`,
    `before=$(stat -c '%d:%i:%F' -- "$path") || exit $?`,
    `if [ -L "$path" ]; then`,
    `  printf '%s\\n' 'refuses to operate through symlink' >&2`,
    `  exit 1`,
    `fi`,
    `after=$(stat -c '%d:%i:%F' -- "$path") || exit $?`,
    `if [ "$before" != "$after" ]; then`,
    `  printf '%s\\n' 'metadata target changed before ${kind}' >&2`,
    `  exit 1`,
    `fi`,
    operation,
  ].join("\n")
}

export async function readOwnership(
  ssh: SshConnection,
  remotePath: string
): Promise<FileOwnership> {
  const raw = await ssh.output(`stat -c '%a %U %G' ${shellQuote(remotePath)}`)
  const [mode = "", owner = "", group = ""] = raw.trim().split(/\s+/v)
  return { group, mode, owner }
}

export function normalizeMode(mode: string): string {
  return mode.startsWith("0") ? mode : `0${mode}`
}

function ownershipComponentMatches(expected: string, actual: string): boolean {
  return expected === "" || actual === expected
}

function groupOwnershipMatches(
  expectsGroup: boolean,
  expectedGroup: string,
  actualGroup: string
): boolean {
  if (!expectsGroup) return true
  return ownershipComponentMatches(expectedGroup, actualGroup)
}

export async function resolveWriteMode(
  ssh: SshConnection,
  remotePath: string,
  explicitMode?: string
): Promise<string> {
  if (explicitMode != null) return explicitMode
  const exists = await ssh.exists(remotePath)
  if (!exists) return DEFAULT_FILE_WRITE_MODE

  const ownership = await readOwnership(ssh, remotePath)
  return normalizeMode(ownership.mode)
}

export async function applyFileMetadata(
  ssh: SshConnection,
  remotePath: string,
  options?: { mode?: string; owner?: string }
): Promise<ModuleResult | null> {
  if (options?.mode == null && options?.owner == null) return null

  // R-0000133: chmod/chown follow symlinks. Refusing here prevents the caller
  // (e.g. file.template.apply) from silently rewriting the mode or ownership
  // of the symlink target — which is almost never the intent and may cross
  // privilege boundaries.
  if (await isSymlink(ssh, remotePath)) {
    return failed(
      `[file metadata: ${remotePath}] refuses to operate through symlink — chmod/chown would follow the link`
    )
  }

  if (options.mode != null) {
    validateMode(options.mode)
    // R-0000269: chmod errors (read-only fs, EPERM after a SELinux relabel,
    // missing user/group) must surface as a failedCommand ModuleResult so
    // callers like file.template.apply can return the maskable failure
    // through the runner pipeline instead of letting an unguarded
    // CommandError propagate.
    const chmodResult = await ssh.exec(
      renderGuardedMetadataCommand("chmod", remotePath, options.mode),
      EXEC_OPTS
    )
    if (chmodResult.code !== 0) {
      return failedCommand(`[file metadata: ${remotePath}] chmod failed`, chmodResult)
    }
  }

  if (options.owner != null) {
    const chownResult = await ssh.exec(
      renderGuardedMetadataCommand("chown", remotePath, options.owner),
      EXEC_OPTS
    )
    if (chownResult.code !== 0) {
      return failedCommand(`[file metadata: ${remotePath}] chown failed`, chownResult)
    }
  }

  return null
}

export function ownershipMatches(
  current: FileOwnership,
  options?: { mode?: string; owner?: string }
): boolean {
  if (options?.mode != null && current.mode !== options.mode.replace(/^0+/v, "")) return false
  if (options?.owner == null) return true

  const expectsGroup = options.owner.includes(":")
  const [expectedOwner, expectedGroup = ""] = options.owner.split(":", 2)
  if (!ownershipComponentMatches(expectedOwner, current.owner)) return false
  if (!groupOwnershipMatches(expectsGroup, expectedGroup, current.group)) return false
  return true
}

export function createMetadataModule(
  kind: "chmod" | "chown",
  remotePath: string,
  value: string
): Module {
  const name = `file.${kind}: ${remotePath}`

  return {
    async apply(ssh: null | SshConnection): Promise<ModuleResult> {
      if (!ssh) return failed(`[${name}] SSH connection is required`)

      // R-0000133: explicitly reject symlinks so chmod/chown cannot follow the
      // link and rewrite mode/owner of the target. `[ -L path ]` matches even
      // when the link is dangling (`[ -e path ]` returns false).
      if (await isSymlink(ssh, remotePath)) {
        return failed(
          `[${name}] refuses to operate through symlink — ${kind} would follow the link`
        )
      }

      if (kind === "chmod") validateMode(value)

      const command =
        kind === "chmod"
          ? renderGuardedMetadataCommand("chmod", remotePath, value)
          : renderGuardedMetadataCommand("chown", remotePath, value)
      // R-0000269: capture chmod/chown exit codes so failures surface as a
      // failedCommand ModuleResult instead of an unguarded CommandError.
      const result = await ssh.exec(command, EXEC_OPTS)
      if (result.code !== 0) {
        return failedCommand(`[${name}] ${kind} failed`, result)
      }
      return { status: "changed" }
    },
    async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
      if (!ssh) return NEEDS_APPLY
      if (!(await ssh.exists(remotePath))) return NEEDS_APPLY
      // R-0000133: symlinks are never "ok" because apply will refuse to follow
      // them. Reporting NEEDS_APPLY here defers the failure to apply, which
      // surfaces the dedicated error message instead of silently passing.
      if (await isSymlink(ssh, remotePath)) return NEEDS_APPLY

      const ownership = await readOwnership(ssh, remotePath)
      const matches = kind === "chmod" ? { mode: value } : { owner: value }
      return ownershipMatches(ownership, matches) ? "ok" : NEEDS_APPLY
    },
    name,
  }
}
