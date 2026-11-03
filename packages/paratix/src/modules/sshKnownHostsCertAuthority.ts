import { failed } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { assertValidGroupName } from "./posixNames.js"
import {
  type KnownHostsCaParameters,
  knownHostsCaParameters,
  type KnownHostsCertAuthorityOptions,
  reconcileKnownHostsCa,
} from "./sshKnownHostsCaValidation.js"
import {
  inspectKnownHosts,
  knownHostsCommand,
  KnownHostsFileError,
  knownHostsMetadataMatches,
  type KnownHostsOwner,
  knownHostsTarget,
  type KnownHostsTarget,
  withKnownHostsLock,
  writeKnownHosts,
} from "./sshKnownHostsFiles.js"

const PASSWD_FIELD_COUNT = 7

async function resolveCaTarget(
  ssh: SshConnection,
  user: string
): Promise<{ owner: KnownHostsOwner; target: KnownHostsTarget }> {
  const passwdOutput = await knownHostsCommand(ssh, `getent passwd ${shellQuote(user)}`)
  const record = passwdOutput.trim()
  const fields = record.split(":")
  if (fields.length !== PASSWD_FIELD_COUNT || fields[0] !== user || /[\n\r]/v.test(record)) {
    throw new KnownHostsFileError(`failed to resolve Unix account: ${user}`)
  }
  const target = knownHostsTarget(fields[5])
  const groupOutput = await knownHostsCommand(ssh, `id -gn ${shellQuote(user)}`)
  const group = groupOutput.trim()
  assertValidGroupName(group)
  return { owner: { group, user }, target }
}

async function runKnownHostsCa(
  ssh: null | SshConnection,
  parameters: KnownHostsCaParameters,
  apply: boolean
): Promise<ModuleResult> {
  const name = `ssh.knownHostsCertAuthority: ${parameters.user} (${parameters.state})`
  if (ssh === null) return failed(`[${name}] SSH connection is required`)
  try {
    const { owner, target } = await resolveCaTarget(ssh, parameters.user)
    const section = async (): Promise<ModuleResult> => {
      const original = await inspectKnownHosts(ssh, target)
      const content = reconcileKnownHostsCa(original.content, parameters)
      const contentMatches = content === original.content
      const metadataMatches =
        parameters.state === "absent" || knownHostsMetadataMatches(original, owner)
      if (contentMatches && metadataMatches) return { status: "ok" }
      if (!apply) return { status: "changed" }
      return writeKnownHosts(ssh, { content, name, original, owner, target })
    }
    // Checks and dry-runs never acquire a remote lock or create any filesystem artifact.
    return apply ? await withKnownHostsLock(ssh, target, { name, section }) : await section()
  } catch (error) {
    return failed(`[${name}] ${error instanceof Error ? error.message : String(error)}`)
  }
}

/**
 * Manage one host-certificate CA in an existing Unix user's known_hosts.
 *
 * The key identifies the resource by algorithm plus decoded key bytes, using
 * canonical base64; input therefore must use strict canonical base64 and an
 * optional key comment does not affect identity. Patterns are positive OpenSSH
 * patterns, sorted and deduplicated; negations are rejected. Removing a CA never
 * requires its previous host list: `hosts` is an optional validation-only input
 * when `state` is `"absent"`. Other CAs, raw host keys, revocations, and unrelated
 * lines are preserved. Present enforces the target user's primary-group ownership,
 * directory 0700, and file 0600. Checks and dry-runs are read-only, including
 * unsafe-path diagnostics. The target is the specified user's `~/.ssh/known_hosts`,
 * not the controller's or the SSH session user's file. Applies use the same
 * canonical-path cooperative mutex as `ssh.knownHosts`; it serializes cooperating
 * Paratix writers but does not coordinate unrelated external writers.
 *
 * @param user - The existing Unix user whose home is resolved on the target.
 * @param options - A complete raw public key, positive host patterns, and desired state.
 * @returns A module managing only this user's matching CA entry.
 */
export function knownHostsCertAuthority(
  user: string,
  options: KnownHostsCertAuthorityOptions
): Module {
  const parameters = knownHostsCaParameters(user, options)
  return {
    async _applyDryRun(ssh) {
      return runKnownHostsCa(ssh, parameters, false)
    },
    async apply(ssh) {
      return runKnownHostsCa(ssh, parameters, true)
    },
    async check(ssh) {
      const result = await runKnownHostsCa(ssh, parameters, false)
      return result.status === "ok" ? "ok" : NEEDS_APPLY
    },
    name: `ssh.knownHostsCertAuthority: ${user} (${parameters.state})`,
  }
}
