import { posix } from "node:path"

import type { SshConnection } from "../types.js"
import type { CertificateFile } from "./sshCertificateFiles.js"

import { shellQuote } from "../ssh.js"
import { includePatterns } from "./sshCertificateConfig.js"
import { contentHash, inspectCertificateFile } from "./sshCertificateFiles.js"
import {
  collectEffectiveSshdDirectiveValues,
  findNonMatchingEffectiveSshdSetting,
  parseSshdConfigLine,
} from "./sshdConfigHelpers.js"
import { SSHD_VERIFY_ADDRESS, SSHD_VERIFY_HOST } from "./sshdIncludeStaging.js"
import {
  SSHD_MATCH_DROP_IN_DIRECTORY,
  sshdMatchCriteriaMatch,
  type SshdMatchSpec,
} from "./sshdMatchSpec.js"

/** The main sshd configuration whose top-level Include loads the drop-in. */
export const SSHD_CONFIG = "/etc/ssh/sshd_config"
const DROP_IN_INCLUDE = `${SSHD_MATCH_DROP_IN_DIRECTORY}/*.conf`

/** The drop-in file to publish: `content` is `undefined` for removal; `original` is its current state. */
export type DropIn = { content?: string } & CertificateFile

/** Expected, user-facing refusal; the live configuration is untouched. */
export class SshdMatchError extends Error {
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = "SshdMatchError"
  }
}

// True when `Include /etc/ssh/sshd_config.d/*.conf` appears before the first Match.
function hasTopLevelDropInInclude(content: string): boolean {
  for (const line of content.split(/\r?\n/v)) {
    const parsed = parseSshdConfigLine(
      line.replace(/^(?<keyword>\s*[A-Za-z][A-Za-z0-9]*)\s*=\s*/v, "$<keyword> ")
    )
    const directive = parsed?.directive.toLowerCase()
    if (parsed === null || directive === undefined) continue
    if (directive === "match") return false
    if (
      directive === "include" &&
      includePatterns(parsed.value).some((pattern) => posix.normalize(pattern) === DROP_IN_INCLUDE)
    )
      return true
  }
  return false
}

/**
 * Read the main configuration; `present` requires the drop-in Include.
 * @param ssh - Target connection.
 * @param spec - Normalized module specification.
 * @returns The main configuration content.
 */
export async function readMainConfig(ssh: SshConnection, spec: SshdMatchSpec): Promise<string> {
  const content = await ssh.readFile(SSHD_CONFIG)
  // Removing a drop-in never needs the Include; adding one without it would be inert.
  if (spec.state === "present" && !hasTopLevelDropInInclude(content)) {
    throw new SshdMatchError(
      `${SSHD_CONFIG} has no top-level "Include ${DROP_IN_INCLUDE}" before its first Match; ` +
        "add it manually (Paratix never adds it)"
    )
  }
  return content
}

/**
 * Inspect the current drop-in and prove that Paratix owns it.
 * @param ssh - Target connection.
 * @param spec - Normalized module specification.
 * @returns The desired content (`undefined` for `absent`) and the original file state.
 * @throws {SshdMatchError} When the file changed while being read or its first line is not the marker.
 */
export async function inspectDropIn(ssh: SshConnection, spec: SshdMatchSpec): Promise<DropIn> {
  const original = await inspectCertificateFile(ssh, spec.path, { label: "sshd.match drop-in" })
  const content = spec.state === "present" ? spec.content : undefined
  if (original === null) return { content, original, path: spec.path }
  const current = await ssh.readFile(spec.path)
  if (contentHash(current) !== original.hash)
    throw new SshdMatchError(`Concurrent modification: ${spec.path}`)
  if (current.split("\n")[0] !== spec.marker) {
    throw new SshdMatchError(
      `${spec.path} exists without the marker "${spec.marker}"; ` +
        "it is not managed by this module and is neither overwritten nor removed"
    )
  }
  return { content, original, path: spec.path }
}

async function accountGroups(ssh: SshConnection, user: string): Promise<null | string[]> {
  const result = await ssh.exec(`id -Gn -- ${shellQuote(user)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code !== 0) return null
  return result.stdout
    .trim()
    .split(/\s+/v)
    .filter((group) => group.length > 0)
}

/**
 * Refuse criteria that match the user of the running Paratix connection (the
 * sudo-independent login user from `getConnectionInfo()`), unless
 * `allowConnectionUser` is set. Group criteria are resolved with `id -Gn --`;
 * unresolvable groups are treated as a possible lockout.
 * @param ssh - Target connection.
 * @param spec - Normalized module specification.
 * @throws {SshdMatchError} When the criteria match, or may match, the connection user.
 */
export async function assertConnectionUserUnmatched(
  ssh: SshConnection,
  spec: SshdMatchSpec
): Promise<void> {
  if (spec.allowConnectionUser) return
  // Commands run through sudo, so `id -un` would always report root.
  const user = ssh.getConnectionInfo().user
  const groups = spec.groups.length > 0 ? await accountGroups(ssh, user) : []
  const matches = sshdMatchCriteriaMatch(spec, { groups, user })
  if (matches === false) return
  throw new SshdMatchError(
    matches === undefined
      ? `cannot determine the groups of the Paratix connection user ${user}; refusing a possible lockout`
      : `the criteria match the Paratix connection user ${user}; a later run could be locked out ` +
          "(set allowConnectionUser: true to accept this deliberately)"
  )
}

/**
 * Why the effect check for the verify user cannot run yet: the account does
 * not exist, or it exists but belongs to none of the criteria groups (a user
 * or group membership the same run may still create). `undefined` means ready.
 * Any non-zero exit of `id -Gn` counts as `missing`, so the message also
 * covers an account that exists but cannot be resolved.
 */
export type VerifyUserPending = "missing" | "not-member" | undefined

/**
 * Resolve whether the verify user exists and, for a group criterion, belongs
 * to one of the listed groups.
 * @param ssh - Target connection.
 * @param spec - Normalized module specification.
 * @returns `undefined` when the effect check can run, otherwise the pending reason.
 */
export async function verifyUserPending(
  ssh: SshConnection,
  spec: SshdMatchSpec
): Promise<VerifyUserPending> {
  const groups = await accountGroups(ssh, spec.verifyUser)
  if (groups === null) return "missing"
  if (spec.groups.length > 0 && !groups.some((group) => spec.groups.includes(group)))
    return "not-member"
  return undefined
}

/**
 * Describe a pending verify-user state.
 * @param spec - Normalized module specification.
 * @param pending - The pending reason from {@link verifyUserPending}.
 * @returns A sentence fragment starting with the verify user.
 */
export function verifyUserPendingText(
  spec: SshdMatchSpec,
  pending: Exclude<VerifyUserPending, undefined>
): string {
  return pending === "missing"
    ? `verify user ${spec.verifyUser} does not exist or cannot be resolved`
    : `verify user ${spec.verifyUser} is not a member of ${spec.groups.join(", ")}`
}

/**
 * Assert that `sshd -T` output reports every configured directive value.
 * @param output - Output of `sshd -T -C` for the verify user.
 * @param spec - Normalized module specification.
 * @param source - Label of the output's origin, used in the message.
 * @throws {SshdMatchError} Naming the first directive whose effective value differs.
 */
export function assertEffective(output: string, spec: SshdMatchSpec, source: string): void {
  const directive = findNonMatchingEffectiveSshdSetting(output, spec.settings)
  if (directive === undefined) return
  const actual = collectEffectiveSshdDirectiveValues(output, directive).join(" ") || "<missing>"
  throw new SshdMatchError(
    `${directive}: expected ${spec.settings[directive] ?? ""} for user ${spec.verifyUser} ` +
      `(${SSHD_VERIFY_HOST}, ${SSHD_VERIFY_ADDRESS}), ${source} reports ${actual}; the first ` +
      "obtained value wins, so an earlier sshd_config.d drop-in or Match block sets it first " +
      "(rename the drop-in or adjust the Match order)"
  )
}
