import { failed } from "../moduleFailure.js"
import { shellQuote, validateMode } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

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

export async function readOwnership(
  ssh: SshConnection,
  remotePath: string
): Promise<FileOwnership> {
  const raw = await ssh.output(`stat -c '%a %U %G' ${shellQuote(remotePath)}`)
  const [mode = "", owner = "", group = ""] = raw.trim().split(" ")
  return { group, mode, owner }
}

export function normalizeMode(mode: string): string {
  return mode.startsWith("0") ? mode : `0${mode}`
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
): Promise<void> {
  if (options?.mode != null) {
    validateMode(options.mode)
    await ssh.exec(`chmod ${shellQuote(options.mode)} ${shellQuote(remotePath)}`, {
      silent: true,
    })
  }

  if (options?.owner != null) {
    await ssh.exec(renderChownCommand(options.owner, remotePath), {
      silent: true,
    })
  }
}

export function ownershipMatches(
  current: FileOwnership,
  options?: { mode?: string; owner?: string }
): boolean {
  if (options?.mode != null && current.mode !== options.mode.replace(/^0+/v, "")) return false
  if (options?.owner == null) return true

  const expectsGroup = options.owner.includes(":")
  const [expectedOwner, expectedGroup = ""] = options.owner.split(":", 2)
  if (current.owner !== expectedOwner) return false
  if (expectsGroup && current.group !== expectedGroup) return false
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

      if (kind === "chmod") validateMode(value)

      const command =
        kind === "chmod"
          ? `chmod ${shellQuote(value)} ${shellQuote(remotePath)}`
          : renderChownCommand(value, remotePath)
      await ssh.exec(command, { silent: true })
      return { status: "changed" }
    },
    async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
      if (!ssh) return NEEDS_APPLY
      if (!(await ssh.exists(remotePath))) return NEEDS_APPLY

      const ownership = await readOwnership(ssh, remotePath)
      const matches = kind === "chmod" ? { mode: value } : { owner: value }
      return ownershipMatches(ownership, matches) ? "ok" : NEEDS_APPLY
    },
    name,
  }
}
