/* eslint-disable max-lines -- apt module variants share helper code and fixtures */
import type { UpgradeOptions } from "./package.js"

import { failed, failedCommand, firstNonEmptyLine } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import {
  type ExecOptions,
  type Module,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"
import {
  applyAptKey,
  normalizeOpenPgpFingerprint,
  validateAptKeyUrl,
  verifyAptKeyFingerprint,
} from "./aptKeyHelpers.js"
import { ensureAptKeyringDirectorySymlinkFree } from "./aptKeyStaging.js"
import { hexHashesEqual, sha256String } from "./fileHelpers.js"
import { applyWithFlagLock, hasFlag, setFlag, setVersionedFlag } from "./moduleHelpers.js"
import { isSymlink } from "./remoteFileChecks.js"

const NONINTERACTIVE = "DEBIAN_FRONTEND=noninteractive"
const APT_REPOSITORY_MODE = "0644"
const APT_REPOSITORY_HASH_LENGTH = 16
const APT_KEYRING_DIRECTORY = "/etc/apt/keyrings"

// R-0000098: apt resource names land directly in shell paths like
// `/etc/apt/keyrings/${name}.gpg` and `/etc/apt/sources.list.d/${name}.list`.
// Reject any value that could resolve to a path-traversal segment (`..`),
// contain a path separator, or otherwise escape the intended directory.
// The pattern allows word characters, dots and dashes; the explicit
// `..` reject below forbids the only single-character-class form that
// could still produce a traversal segment.
const APT_RESOURCE_NAME_PATTERN = /^[\w.\-]+$/v

function validateAptResourceName(name: string): void {
  if (name.length === 0 || name.includes("..") || !APT_RESOURCE_NAME_PATTERN.test(name)) {
    throw new Error(
      `apt: name must match ${String(APT_RESOURCE_NAME_PATTERN)} and must not contain '..', got: ${JSON.stringify(name)}`
    )
  }
}

function buildRepositoryUpdateFlag(
  name: string,
  expectedContent: string
): {
  flagName: string
  flagPrefix: string
} {
  const flagPrefix = `apt-repository-${sha256String(name).slice(0, APT_REPOSITORY_HASH_LENGTH)}-`
  return {
    flagName: `${flagPrefix}${sha256String(expectedContent).slice(0, APT_REPOSITORY_HASH_LENGTH)}`,
    flagPrefix,
  }
}

type AptRepositorySnapshot =
  | {
      content: string
      exists: true
      // R-0000702: device:inode identity captured alongside the content hash.
      // `null` when the stat probe failed (older coreutils variants, custom
      // busybox without `-c`, …); the integrity check tolerates a missing
      // identity rather than refusing to proceed on benign environments.
      identity: null | string
    }
  | { exists: false }

/**
 * R-0000702: probe the device:inode pair of the sources.list. Combining this
 * with the SHA-256 hash check in {@link ensureAptRepositorySnapshotStillCurrent}
 * pins the integrity check to a concrete inode, so a swap that replaces the
 * file with a fresh inode containing byte-identical content is detected.
 *
 * Returns `null` when `stat` cannot produce the identity (non-zero exit,
 * empty stdout). Callers must treat `null` as "unknown" — the SHA-256 guard
 * remains the primary check.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param filePath - Absolute path of the sources.list file to probe.
 * @returns The `device:inode` identity string, or `null` when unavailable.
 */
async function probeAptRepositoryInodeIdentity(
  ssh: SshConnection,
  filePath: string
): Promise<null | string> {
  const result = await ssh.exec(`stat -c '%d:%i' ${shellQuote(filePath)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code !== 0) return null
  const trimmed = result.stdout.trim()
  return trimmed === "" ? null : trimmed
}

async function snapshotAptRepository(
  ssh: SshConnection,
  filePath: string
): Promise<AptRepositorySnapshot> {
  // R-0000235: only treat regular files (not symlinks) as existing snapshots.
  // `[ -f path ]` follows symlinks, so without the explicit `-L` rejection a
  // symlinked sources.list would be read through to an attacker-controlled
  // target. Callers must also guard against writing through symlinks before
  // invoking this helper.
  const exists = await ssh.test(
    `[ -f ${shellQuote(filePath)} ] && [ ! -L ${shellQuote(filePath)} ]`
  )
  if (!exists) return { exists: false }
  const content = await ssh.readFile(filePath)
  // R-0000702: capture the device:inode pair so a concurrent swap that
  // replaces the file with byte-identical content on a new inode is
  // detected by `ensureAptRepositorySnapshotStillCurrent`.
  const identity = await probeAptRepositoryInodeIdentity(ssh, filePath)
  return { content, exists: true, identity }
}

type RepositoryRollbackParameters = {
  // R-0000753: bytes apply wrote to the sources.list just before the failed
  // `apt-get update`; required so `restoreAptRepository` can refuse the
  // rollback when the file has drifted in the failure window.
  appliedContent: string
  filePath: string
  name: string
  previousRepository: AptRepositorySnapshot
  ssh: SshConnection
  updateResult: { code: number; stderr: string; stdout: string }
}

/**
 * Run the rollback path after `apt-get update` rejects a freshly written
 * repository file. Restores the previous on-disk state and re-runs
 * `apt-get update` so apt's in-memory cache matches the restored .list
 * (R-0000163). The original update failure is preserved as the primary
 * error; a follow-up failure is appended as context.
 *
 * @param parameters - Rollback context.
 * @returns A `failed` ModuleResult describing the original update failure
 *   plus, when applicable, the rollback-update failure context.
 */
async function rollbackRepositoryAfterUpdateFailure(
  parameters: RepositoryRollbackParameters
): Promise<ModuleResult> {
  const { appliedContent, filePath, name, previousRepository, ssh, updateResult } = parameters
  const rollback = await restoreAptRepository({
    appliedContent,
    filePath,
    snapshot: previousRepository,
    ssh,
  })
  if (rollback !== "ok") {
    // R-0000753: when the rollback is refused (drift detected, or
    // restoreAptRepository surfaced a structured failure), combine the
    // original update failure with the rollback refusal so the operator
    // sees both reasons. Mirrors `combineComposeSystemdRollbackFailure`.
    const rollbackMessage = rollback.error?.message ?? "rollback failed"
    return failedCommand(
      `[apt.repository] apt-get update failed for ${name}; rollback refused: ${rollbackMessage}`,
      updateResult
    )
  }
  const rollbackUpdate = await ssh.exec(`${NONINTERACTIVE} apt-get update`, {
    ignoreExitCode: true,
    silent: true,
  })
  const failureMessage = `[apt.repository] apt-get update failed for ${name}`
  if (rollbackUpdate.code !== 0) {
    return failedCommand(
      `${failureMessage}; rollback succeeded but apt-get update on the restored sources also failed (exit code ${String(rollbackUpdate.code)}): ${firstNonEmptyLine(rollbackUpdate.stderr) ?? firstNonEmptyLine(rollbackUpdate.stdout) ?? "no output"}`,
      updateResult
    )
  }
  return failedCommand(failureMessage, updateResult)
}

/**
 * Compare the live sources.list state against a snapshot that recorded an
 * existing file. Surfaces the specific drift (disappeared, content changed,
 * inode swap) so the caller can refuse to overwrite a mutated file.
 *
 * @param parameters - Comparison context.
 * @param parameters.filePath - Absolute path of the sources.list on the remote host.
 * @param parameters.name - Repository name used in failure messages.
 * @param parameters.snapshot - The recorded snapshot content and inode identity.
 * @param parameters.snapshot.content - Bytes captured from the file at snapshot time.
 * @param parameters.snapshot.identity - `device:inode` identity captured at snapshot time, or `null` when unavailable.
 * @param parameters.ssh - Active SSH connection to the remote host.
 * @returns A failed ModuleResult on any divergence, otherwise `null`.
 */
async function ensureExistingSourcesListUnchanged(parameters: {
  filePath: string
  name: string
  snapshot: { content: string; identity: null | string }
  ssh: SshConnection
}): Promise<ModuleResult | null> {
  const { filePath, name, snapshot, ssh } = parameters
  const currentRemoteHash = await ssh.sha256(filePath)
  if (currentRemoteHash === null) {
    return failed(
      `[apt.repository] sources.list disappeared between snapshot and write for ${name} at ${filePath}; refusing to proceed`
    )
  }
  const expectedSnapshotHash = sha256String(snapshot.content)
  if (!hexHashesEqual(currentRemoteHash, expectedSnapshotHash)) {
    return failed(
      `[apt.repository] sources.list changed between snapshot and write for ${name} at ${filePath}; refusing to proceed`
    )
  }
  // R-0000702: compare device:inode identity to detect a content-preserving
  // inode swap. Skip the check when either side is `null` (older coreutils
  // could not produce the identity) so benign environments are not blocked.
  if (snapshot.identity !== null) {
    const currentIdentity = await probeAptRepositoryInodeIdentity(ssh, filePath)
    if (currentIdentity !== null && currentIdentity !== snapshot.identity) {
      return failed(
        `[apt.repository] sources.list inode changed between snapshot and write for ${name} at ${filePath}; refusing to proceed`
      )
    }
  }
  return null
}

/**
 * R-0000566: ensure the sources.list content on disk still matches the
 * snapshot captured a moment earlier in `apply`. Without this guard a
 * concurrent writer could mutate the file between `snapshotAptRepository`
 * (read) and the subsequent `ssh.writeFile` (write), so a later rollback
 * would restore the *snapshot* content — not the actual pre-mutation state
 * the operator observed — and silently mask the concurrent change.
 *
 * R-0000702: in addition to comparing SHA-256 hashes, the on-disk
 * device:inode identity is matched against the snapshot. A concurrent
 * writer could otherwise atomically replace the file with byte-identical
 * content sitting on a new inode (e.g. a freshly mounted overlay or a
 * `mv -T` swap with a prepared duplicate) and slip past a hash-only
 * guard. The symlink probe is also re-run so a fresh `[ -L ]` swap that
 * appeared after the apply-time guard cannot smuggle a symlinked target
 * into the subsequent `ssh.writeFile`.
 *
 * @param parameters - Integrity-check context.
 * @param parameters.filePath - The sources.list path on the remote host.
 * @param parameters.name - The repository name, used in failure messages.
 * @param parameters.snapshot - The snapshot taken at the start of apply.
 * @param parameters.ssh - The active SSH connection.
 * @returns A failed {@link ModuleResult} when the on-disk state diverges
 *   from the snapshot, otherwise `null`.
 */
async function ensureAptRepositorySnapshotStillCurrent(parameters: {
  filePath: string
  name: string
  snapshot: AptRepositorySnapshot
  ssh: SshConnection
}): Promise<ModuleResult | null> {
  const { filePath, name, snapshot, ssh } = parameters
  // R-0000702: defense in depth — a symlink may have appeared between the
  // apply-time `isSymlink` guard and this point. Re-check so a TOCTOU swap
  // cannot let `ssh.writeFile` follow the link to an attacker-controlled
  // target. Matches the second-guard pattern in compose.ts (R-0000677).
  if (await isSymlink(ssh, filePath)) {
    return failed(
      `[apt.repository] sources.list became a symlink between snapshot and write for ${name} at ${filePath}; refusing to proceed`
    )
  }
  if (snapshot.exists) {
    return ensureExistingSourcesListUnchanged({
      filePath,
      name,
      snapshot: { content: snapshot.content, identity: snapshot.identity },
      ssh,
    })
  }
  const currentRemoteHash = await ssh.sha256(filePath)
  if (currentRemoteHash !== null) {
    return failed(
      `[apt.repository] sources.list appeared between snapshot and write for ${name} at ${filePath}; refusing to proceed`
    )
  }
  return null
}

/**
 * R-0000753: bytes apply wrote to the sources.list just before the failed
 * `apt-get update`. Used by `restoreAptRepository` to verify the file is
 * still in the post-apply state before rolling it back to the snapshot.
 * `null` means "no apply-time content was produced" (rollback paths that do
 * not run through the standard apply branch, e.g. an early-return failure).
 */
type AptRepositoryAppliedContent = null | string

async function restoreAptRepository(parameters: {
  appliedContent: AptRepositoryAppliedContent
  filePath: string
  snapshot: AptRepositorySnapshot
  ssh: SshConnection
}): Promise<"ok" | ModuleResult> {
  const { appliedContent, filePath, snapshot, ssh } = parameters
  if (snapshot.exists) {
    // R-0000235: defense in depth — refuse to restore through a symlink that
    // may have appeared between the snapshot and the rollback. The apply
    // guard runs once at the start of apply; a symlink that materializes
    // afterwards must not let writeFile follow it to an arbitrary target.
    if (await isSymlink(ssh, filePath)) {
      return failed(`[apt.repository] refuses to restore through symlink at ${filePath}`)
    }
    // R-0000753: refuse rollback when the sources.list on disk has drifted
    // from the bytes apply just wrote. After a failed `apt-get update` the
    // file is supposed to still hold the new content, so any divergence
    // means an operator hotfix, another agent or a packaging script touched
    // the file in the failure window — overwriting it with the snapshot
    // would silently clobber that intervention. The drift refusal does not
    // mask the original update failure: the caller composes a combined
    // message in the same shape as `combineComposeSystemdRollbackFailure`.
    if (appliedContent !== null) {
      const driftFailure = await detectAptRepositoryDriftBeforeRollback(
        ssh,
        filePath,
        appliedContent
      )
      if (driftFailure !== null) return driftFailure
    }
    await ssh.writeFile(filePath, snapshot.content, { mode: APT_REPOSITORY_MODE })
    return "ok"
  }
  const removeResult = await ssh.exec(`rm -f ${shellQuote(filePath)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (removeResult.code !== 0) {
    return failedCommand("[apt.repository] failed to rollback repository file", removeResult)
  }
  return "ok"
}

/**
 * R-0000753: probe whether the on-disk sources.list still matches the bytes
 * apply just wrote. If not, the file has drifted between writeFile and
 * rollback — typically an operator hotfix in the apt-get-update window —
 * and we must refuse to overwrite it with the snapshot. Returns `null`
 * when no drift is detected, otherwise a failed `ModuleResult` the caller
 * surfaces as the rollback outcome. A missing remote hash (sha256 returned
 * `null`) is treated as drift so a rollback never silently writes through
 * a file whose state we cannot verify.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param filePath - Absolute path of the sources.list file to verify.
 * @param appliedContent - The bytes apply wrote to `filePath` before the
 *   failed `apt-get update`.
 * @returns `null` when content matches, otherwise a failed `ModuleResult`.
 */
async function detectAptRepositoryDriftBeforeRollback(
  ssh: SshConnection,
  filePath: string,
  appliedContent: string
): Promise<ModuleResult | null> {
  const currentHash = await ssh.sha256(filePath)
  if (currentHash === null) {
    return failed(
      `[apt.repository] refuses to roll back ${filePath}: current sha256 unavailable, file may have drifted since snapshot`
    )
  }
  const appliedHash = sha256String(appliedContent)
  if (hexHashesEqual(currentHash, appliedHash)) return null
  return failed(
    `[apt.repository] refuses to roll back ${filePath}: file has drifted since snapshot (expected ${appliedHash}, found ${currentHash})`
  )
}

const APT_BASE_EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const APT_SOURCE_LINE_BREAK_PATTERN = /[\r\n]/v

function aptExecOptions(options?: UpgradeOptions): ExecOptions {
  if (options?.timeout === undefined) return APT_BASE_EXEC_OPTS
  return { ...APT_BASE_EXEC_OPTS, timeout: options.timeout }
}

const PPA_PREFIX = "ppa:"
const PPA_IDENTIFIER_PATTERN = /^[a-z0-9][a-z0-9+\-]*\/[a-z0-9][a-z0-9+\-]*$/v
/**
 * Parse the output of `debconf-show` into a question-to-value map.
 *
 * Each line has the form `[*] <question>: <value>`. The leading asterisk
 * (marking the currently active value) is stripped, and blank lines are
 * ignored.
 *
 * @param stdout - Raw stdout of `debconf-show <package>`.
 * @returns A map of debconf question names to their current values.
 */
function parseDebconfOutput(stdout: string): Record<string, string> {
  const values: Record<string, string> = {}
  for (const line of stdout.split("\n")) {
    const colonIndex = line.indexOf(":")
    if (colonIndex === -1) continue
    const rawQuestion = line.slice(0, colonIndex).replace(/^\s*\*?\s*/v, "")
    if (rawQuestion) {
      values[rawQuestion] = line.slice(colonIndex + 1).trim()
    }
  }
  return values
}

// R-0000104: short hash length for the per-package and per-selections
// segments of the debconf marker flag. 16 hex chars = 64 bits, which
// gives a collision-resistant identifier without bloating the flag
// file name.
const APT_DEBCONF_HASH_LENGTH = 16
const DEBCONF_FIELD_SEPARATOR_PATTERN = /\s/v
const DEBCONF_LINE_BREAK_PATTERN = /[\r\n]/v

function validateDebconfPackageName(packageName: string): ModuleResult | null {
  if (
    packageName.length === 0 ||
    packageName.startsWith("-") ||
    DEBCONF_FIELD_SEPARATOR_PATTERN.test(packageName)
  ) {
    return failed(
      `[apt.debconf] packageName must not be empty, start with '-', or contain whitespace: ${JSON.stringify(packageName)}`
    )
  }
  return null
}

function validateDebconfQuestion(packageName: string, question: string): ModuleResult | null {
  if (question.length === 0 || DEBCONF_FIELD_SEPARATOR_PATTERN.test(question)) {
    return failed(
      `[apt.debconf] question for ${packageName} must not be empty or contain whitespace: ${JSON.stringify(question)}`
    )
  }
  return null
}

function validateDebconfValue(packageName: string, value: string): ModuleResult | null {
  if (DEBCONF_LINE_BREAK_PATTERN.test(value)) {
    return failed(
      `[apt.debconf] selections for ${packageName} must not contain CR or LF characters`
    )
  }
  return null
}

/**
 * Build the marker flag prefix and full flag name for an apt.debconf
 * configuration. The prefix is keyed only to `packageName` so that
 * `setVersionedFlag` deletes stale flags from previous selection sets
 * when the desired selections change. The full flag name additionally
 * encodes a hash of the selections so that drift in the desired values
 * is detected as `needs-apply` instead of being masked by an existing
 * flag.
 *
 * @param packageName - The package name whose debconf selections are pre-seeded.
 * @param selectionsText - Newline-joined `pkg question type value` lines.
 * @returns The flag prefix (for cleanup) and the full flag name.
 */
function buildDebconfFlagInfo(
  packageName: string,
  selectionsText: string
): { flagName: string; flagPrefix: string } {
  const packageHash = sha256String(packageName).slice(0, APT_DEBCONF_HASH_LENGTH)
  const selectionsHash = sha256String(`${packageName}\n${selectionsText}`).slice(
    0,
    APT_DEBCONF_HASH_LENGTH
  )
  const flagPrefix = `apt-debconf-${packageHash}-`
  const flagName = `${flagPrefix}${selectionsHash}`
  return { flagName, flagPrefix }
}

/**
 * Build the newline-joined selections text fed to `debconf-set-selections`.
 *
 * Each line has the form `<package> <question> <type> <value>` and uses
 * the type returned by `resolveDebconfType`. Newline characters in
 * questions or values are rejected up-front because debconf's flat-file
 * format cannot represent them.
 *
 * @param ssh - Active SSH connection used to query debconf types.
 * @param packageName - The package name whose selections are pre-seeded.
 * @param selections - A map of `question -> value` entries.
 * @returns A `failed` ModuleResult on rejection, otherwise the joined text.
 */
async function buildDebconfSelectionsText(
  ssh: SshConnection,
  packageName: string,
  selections: Record<string, string>
): Promise<ModuleResult | string> {
  const packageNameFailure = validateDebconfPackageName(packageName)
  if (packageNameFailure) return packageNameFailure

  const lines: string[] = []
  for (const [question, value] of Object.entries(selections)) {
    const questionFailure = validateDebconfQuestion(packageName, question)
    if (questionFailure) return questionFailure

    const valueFailure = validateDebconfValue(packageName, value)
    if (valueFailure) return valueFailure

    // eslint-disable-next-line no-await-in-loop
    const type = await resolveDebconfType(ssh, question)
    lines.push(`${packageName} ${question} ${type} ${value}`)
  }
  return lines.join("\n")
}

/**
 * Compare the live debconf database for an installed package against
 * the desired selections. Returns `ok` when every requested question
 * already holds the desired value, otherwise `needs-apply`.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param packageName - The package name to probe.
 * @param selections - Desired `question -> value` map.
 * @returns `ok` when the live database matches, otherwise `needs-apply`.
 */
async function checkInstalledDebconfState(
  ssh: SshConnection,
  packageName: string,
  selections: Record<string, string>
): Promise<"needs-apply" | "ok"> {
  const result = await ssh.exec(`debconf-show ${shellQuote(packageName)}`, APT_BASE_EXEC_OPTS)
  if (result.code !== 0) return NEEDS_APPLY

  const currentValues = parseDebconfOutput(result.stdout)
  for (const [question, value] of Object.entries(selections)) {
    if (currentValues[question] !== value) return NEEDS_APPLY
  }
  return "ok"
}

/**
 * Consult the versioned marker flag for an apt.debconf configuration.
 * Used as the fallback idempotency signal when the package is not yet
 * installed and `debconf-show` therefore cannot report state.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param packageName - The package name whose selections are pre-seeded.
 * @param selections - Desired `question -> value` map.
 * @returns `ok` when the marker for the current selections exists,
 *   otherwise `needs-apply`.
 */
async function checkBufferedDebconfMarker(
  ssh: SshConnection,
  packageName: string,
  selections: Record<string, string>
): Promise<"needs-apply" | "ok"> {
  const selectionsTextOrFailure = await buildDebconfSelectionsText(ssh, packageName, selections)
  if (typeof selectionsTextOrFailure !== "string") return NEEDS_APPLY

  const { flagName } = buildDebconfFlagInfo(packageName, selectionsTextOrFailure)
  return (await hasFlag(ssh, flagName)) ? "ok" : NEEDS_APPLY
}

/**
 * Probe whether the given Debian package is installed.
 *
 * Uses `dpkg-query -W -f='${Status}'` and matches the freeform status
 * line against the canonical `install ok installed` token. This avoids
 * false positives for packages that are merely partially installed,
 * unpacked, or whose configuration was removed (`config-files` /
 * `not-installed` / `unpacked` states), where the debconf database
 * may be stale or incomplete.
 *
 * @param ssh - Active SSH connection.
 * @param packageName - The package name to probe.
 * @returns `true` when dpkg reports the package as fully installed.
 */
async function isAptPackageInstalled(ssh: SshConnection, packageName: string): Promise<boolean> {
  const result = await ssh.exec(
    `dpkg-query -W -f='\${Status}' ${shellQuote(packageName)}`,
    APT_BASE_EXEC_OPTS
  )
  if (result.code !== 0) return false
  return result.stdout.trim() === "install ok installed"
}

function validatePpaIdentifier(ppa: string, ppaPath: string): void {
  if (!PPA_IDENTIFIER_PATTERN.test(ppaPath)) {
    throw new Error(
      `apt.repository: PPA identifier must use Launchpad owner/name form with lowercase letters, numbers, '+' or '-', got: ${JSON.stringify(ppa)}`
    )
  }
}

/**
 * Build a Module that adds a Launchpad PPA via `add-apt-repository`.
 *
 * The check phase queries `/etc/apt/sources.list.d/` for the PPA path
 * so that the command is not re-run if the repository is already present.
 *
 * @param ppa - PPA identifier in the form `"ppa:user/name"`.
 * @returns A Module that registers the PPA.
 */
function buildPpaRepository(ppa: string): Module {
  const ppaPath = ppa.slice(PPA_PREFIX.length)
  validatePpaIdentifier(ppa, ppaPath)
  const launchpadContentHost = ["ppa.launchpad", "content.net"].join("")
  const launchpadContentPath = `/${launchpadContentHost}/${ppaPath}/`
  const launchpadPath = `/ppa.launchpad.net/${ppaPath}/`
  const activeSourceLinesCommand =
    "grep -RshE -- '^[[:space:]]*deb(-src)?[[:space:]]' /etc/apt/sources.list.d/ 2>/dev/null"
  return {
    async apply(ssh: null | SshConnection): Promise<ModuleResult> {
      if (!ssh) return failed(`[apt.repository] SSH connection is required for ${ppa}`)
      const result = await ssh.exec(`add-apt-repository -y ${shellQuote(ppa)}`, {
        ignoreExitCode: true,
        silent: true,
      })
      if (result.code !== 0) return failedCommand(`[apt.repository] failed to add ${ppa}`, result)
      return { status: "changed" }
    },
    async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
      if (!ssh) return NEEDS_APPLY
      const checkCommand = [
        `${activeSourceLinesCommand} | grep -Fqs -- ${shellQuote(launchpadContentPath)}`,
        `${activeSourceLinesCommand} | grep -Fqs -- ${shellQuote(launchpadPath)}`,
      ].join(" || ")
      return (await ssh.test(checkCommand)) ? "ok" : NEEDS_APPLY
    },
    name: `apt.repository: ${ppa}`,
  }
}

/**
 * Query the debconf database for the type of a question (e.g. `select`, `string`).
 * Falls back to `"string"` when the type cannot be determined.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param question - Fully-qualified debconf question key.
 * @returns Debconf type string (defaults to `"string"`).
 */
async function resolveDebconfType(ssh: SshConnection, question: string): Promise<string> {
  const metagetCommand = `METAGET ${question} type`
  const typeResult = await ssh.exec(`echo ${shellQuote(metagetCommand)} | debconf-communicate`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (typeResult.code === 0 && typeResult.stdout.trim()) {
    const parts = typeResult.stdout.trim().split(/\s+/v)
    if (parts.length >= 2 && parts[0] === "0") {
      return parts[1]
    }
  }
  return "string"
}

const BRACKETED_SOURCE_RE = /^(?<prefix>deb(?:-src)?)\s+\[(?<opts>[^\]]*)\](?<rest>.*)$/v
const PLAIN_SOURCE_RE = /^(?<prefix>deb(?:-src)?)\s(?<rest>.+)$/v
const SIGNED_BY_OPTION_RE = /(?:^|\s)signed-by=\S+/v

function validateRepositorySourceLine(sourceLine: string): string {
  if (APT_SOURCE_LINE_BREAK_PATTERN.test(sourceLine)) {
    throw new Error("apt.repository: source must be exactly one line")
  }
  const trimmed = sourceLine.trim()
  if (trimmed.length === 0) {
    throw new Error("apt.repository: source must not be empty")
  }
  return trimmed
}

/**
 * Inject a `signed-by=<keyPath>` option into a deb source line.
 *
 * Handles both the bracketed form (`deb [arch=amd64] ...`) and the plain
 * form (`deb https://...`). Non-deb source lines are rejected because they
 * cannot be isolated with a keyring-specific `signed-by` option.
 *
 * @param sourceLine - A single deb/deb-src source line.
 * @param keyPath - Absolute path to the GPG keyring file on the remote host.
 * @returns The source line with the `signed-by` option inserted.
 */
/**
 * R-0000752: assert that the `signed-by` key path is safe to splice into an
 * apt source line. The key path is concatenated verbatim into the bracketed
 * options string, so a value containing `[`, `]` or whitespace would corrupt
 * the option list (and could smuggle additional options through). A relative
 * path would silently break apt's signed-by lookup because the value must be
 * an absolute on-disk path to the keyring file. Today the caller derives the
 * path from `validateAptResourceName`, but the defensive assertion guards
 * against a future caller that passes user-controlled text directly.
 *
 * @param keyPath - The candidate signed-by path.
 * @throws {Error} If `keyPath` is not absolute or contains bracket /
 *   whitespace characters that would corrupt the apt source line.
 */
function assertSafeSignedByKeyPath(keyPath: string): void {
  if (!keyPath.startsWith("/")) {
    throw new Error(
      `apt.repository: signed-by key path must be absolute, got: ${JSON.stringify(keyPath)}`
    )
  }
  // R-0000752: `v` flag treats `[` and `]` as reserved inside character
  // classes, so both must be backslash-escaped.
  if (/[\[\]\s]/v.test(keyPath)) {
    throw new Error(
      `apt.repository: signed-by key path must not contain brackets or whitespace, got: ${JSON.stringify(keyPath)}`
    )
  }
}

function injectSignedBy(sourceLine: string, keyPath: string): string {
  assertSafeSignedByKeyPath(keyPath)
  const withBrackets = BRACKETED_SOURCE_RE.exec(sourceLine)
  if (withBrackets?.groups) {
    const options = SIGNED_BY_OPTION_RE.test(withBrackets.groups.opts)
      ? withBrackets.groups.opts.replace(SIGNED_BY_OPTION_RE, (match) => {
          const prefix = match.startsWith(" ") ? " " : ""
          return `${prefix}signed-by=${keyPath}`
        })
      : `${withBrackets.groups.opts} signed-by=${keyPath}`
    return `${withBrackets.groups.prefix} [${options}]${withBrackets.groups.rest}`
  }
  const withoutBrackets = PLAIN_SOURCE_RE.exec(sourceLine)
  if (withoutBrackets?.groups) {
    return `${withoutBrackets.groups.prefix} [signed-by=${keyPath}] ${withoutBrackets.groups.rest}`
  }
  throw new Error("apt.repository: source must start with deb or deb-src when signedBy is enabled")
}

/**
 * Modules for Debian/Ubuntu-specific apt configuration.
 *
 * Provides four apt-specific helpers:
 * - `debconf` — pre-seed debconf answers for non-interactive installs
 * - `distUpgrade` — run `apt-get dist-upgrade` with full dependency resolution
 * - `key` — import a GPG key into `/etc/apt/keyrings/`
 * - `repository` — add a PPA or custom `.list` source file
 *
 * For installing, removing and upgrading packages use the distro-agnostic
 * `package` module instead.
 *
 * @see pkg
 */
export const apt = {
  /**
   * Set debconf selections for a package so that installs/upgrades
   * can proceed non-interactively with the desired answers.
   *
   * @param packageName - The package name whose debconf questions to pre-seed.
   * @param selections - A map of `question -> value` entries where the key is
   *   the full debconf question name (e.g. `"postfix/main_mailer_type"`).
   * @returns A Module that applies the debconf selections.
   *
   * @example
   * apt.debconf("postfix", {
   *   "postfix/main_mailer_type": "Internet Site",
   *   "postfix/mailname": "example.com",
   * })
   */
  debconf(packageName: string, selections: Record<string, string>): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[apt.debconf] SSH connection is required for ${packageName}`)

        const selectionsTextOrFailure = await buildDebconfSelectionsText(
          ssh,
          packageName,
          selections
        )
        if (typeof selectionsTextOrFailure !== "string") return selectionsTextOrFailure

        const selectionsText = selectionsTextOrFailure
        const selectionValues = Object.values(selections)
        const result = await ssh.exec("debconf-set-selections", {
          ignoreExitCode: true,
          input: selectionsText,
          secrets: selectionValues,
          silent: true,
        })
        if (result.code !== 0)
          return failedCommand(
            `[apt.debconf] failed to set selections for ${packageName}`,
            result,
            selectionValues
          )

        // R-0000104: persist a versioned marker flag so that subsequent
        // `check` runs return `ok` even when the package is not yet
        // installed (in which case `debconf-show` would exit non-zero
        // and yield a permanent `needs-apply`). The flag prefix is keyed
        // to the package, so changing the desired selections evicts the
        // stale flag and `check` will correctly report `needs-apply`.
        const { flagName, flagPrefix } = buildDebconfFlagInfo(packageName, selectionsText)
        // R-0000273: surface persist-flag failures (EROFS/EPERM/ENOSPC) on
        // the standard failure path; the helper no longer throws.
        const flagFailure = await setVersionedFlag(ssh, flagName, flagPrefix)
        if (flagFailure) return flagFailure

        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        if (validateDebconfPackageName(packageName)) return NEEDS_APPLY

        // R-0000104: distinguish between `package installed, drift` and
        // `package not installed, selections buffered`. When the package
        // is installed the live debconf database is the source of truth.
        // When it is not yet installed `debconf-show` exits non-zero and
        // we must instead consult the versioned marker flag set by
        // `apply` to decide whether the buffered selections still match
        // the desired set.
        return (await isAptPackageInstalled(ssh, packageName))
          ? checkInstalledDebconfState(ssh, packageName, selections)
          : checkBufferedDebconfMarker(ssh, packageName, selections)
      },
      name: `apt.debconf: ${packageName}`,
    }
  },

  /**
   * Run `apt-get update && apt-get dist-upgrade` once per dated flag.
   * Performs a full distribution upgrade with dependency resolution.
   *
   * The pipeline is split into three separate SSH commands so that each step
   * gets its own timeout window and produces a precise failure label.
   *
   * The marker is written with `setFlag`: the flag name carries only the
   * date and no call-site identity, so an evicting prefix would be
   * host-global and two `apt.distUpgrade` calls with different dates would
   * delete each other's marker on every run. Retired markers are therefore
   * not pruned, and re-using an earlier date is skipped rather than re-run.
   *
   * @param date - A date string used as the idempotency key (e.g. `"2024-01-15"`).
   * @param options - Optional per-call overrides (e.g. SSH command `timeout`).
   *   The same `timeout` is applied to every step of the dist-upgrade pipeline.
   * @returns A Module that performs the dist-upgrade.
   *
   * @example
   * apt.distUpgrade("2024-01-15")
   * apt.distUpgrade("2024-01-15", { timeout: 900_000 })
   */
  distUpgrade(date: string, options?: UpgradeOptions): Module {
    const flagName = `apt-dist-upgrade-${date}`
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[apt.distUpgrade] SSH connection is required for ${date}`)
        const pipelineOptions = aptExecOptions(options)

        return applyWithFlagLock(ssh, {
          async apply() {
            // R-0000055: run `dpkg --configure -a` first so an interrupted
            // package configuration is healed before the next apt step. The
            // previous order put `apt-get update` first, which would fail on
            // dpkg-broken hosts and never give configure -a a chance to run.
            // Mirrors the order used by package.ts apt-upgrade pipeline.
            const configure = await ssh.exec(
              `${NONINTERACTIVE} dpkg --configure -a`,
              pipelineOptions
            )
            if (configure.code !== 0)
              return failedCommand("[apt.distUpgrade] dpkg --configure -a failed", configure)

            const update = await ssh.exec(`${NONINTERACTIVE} apt-get update`, pipelineOptions)
            if (update.code !== 0)
              return failedCommand("[apt.distUpgrade] apt-get update failed", update)

            const upgrade = await ssh.exec(
              `${NONINTERACTIVE} apt-get dist-upgrade -y`,
              pipelineOptions
            )
            if (upgrade.code !== 0)
              return failedCommand("[apt.distUpgrade] apt-get dist-upgrade failed", upgrade)

            // R-0000273: the flag helper returns a typed
            // `ModuleResult | null`; surface persist failures rather than
            // throwing after a successful dist-upgrade.
            const flagFailure = await setFlag(ssh, flagName)
            if (flagFailure) return flagFailure

            return { status: "changed" }
          },
          flagName,
        })
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return (await hasFlag(ssh, flagName)) ? "ok" : NEEDS_APPLY
      },
      name: `apt.distUpgrade: ${date}`,
    }
  },

  /**
   * Import a GPG key into `/etc/apt/keyrings/` for use with signed repositories.
   * @param name - Key file name (without `.gpg` extension).
   * @param url - URL to download the key from.
   * @param options - Required trust anchor for the downloaded key.
   * @param options.fingerprint - Expected OpenPGP fingerprint of the repository key.
   * @returns A Module that imports the GPG key.
   */
  key(name: string, url: string, options: { fingerprint: string }): Module {
    validateAptResourceName(name)
    validateAptKeyUrl(url)
    const expectedFingerprint = normalizeOpenPgpFingerprint(options.fingerprint)
    const keyringPath = `${APT_KEYRING_DIRECTORY}/${name}.gpg`
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[apt.key] SSH connection is required for ${name}`)

        const preMkdirDirectoryFailure = await ensureAptKeyringDirectorySymlinkFree(ssh, {
          directory: APT_KEYRING_DIRECTORY,
          name,
        })
        if (preMkdirDirectoryFailure != null) return preMkdirDirectoryFailure

        const mkdirResult = await ssh.exec(`mkdir -p ${APT_KEYRING_DIRECTORY}`, {
          ignoreExitCode: true,
          silent: true,
        })
        if (mkdirResult.code !== 0)
          return failedCommand(`[apt.key] failed to create ${APT_KEYRING_DIRECTORY}`, mkdirResult)

        const postMkdirDirectoryFailure = await ensureAptKeyringDirectorySymlinkFree(ssh, {
          directory: APT_KEYRING_DIRECTORY,
          name,
        })
        if (postMkdirDirectoryFailure != null) return postMkdirDirectoryFailure

        return applyAptKey(ssh, { expectedFingerprint, keyringPath, name, url })
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        // R-0000134: a symlink at the keyring path is treated as "not present"
        // so apply runs, where it will refuse the import with a clear error.
        // The combined test prevents `[ -f path ]` from following a symlink
        // and reporting a stale or attacker-controlled target as up-to-date.
        const keyExists = await ssh.test(
          `[ -f ${shellQuote(keyringPath)} ] && [ ! -L ${shellQuote(keyringPath)} ]`
        )
        if (!keyExists) return NEEDS_APPLY

        return (await verifyAptKeyFingerprint({
          expectedFingerprint,
          name,
          path: keyringPath,
          ssh,
        })) === "ok"
          ? "ok"
          : NEEDS_APPLY
      },
      name: `apt.key: ${name}`,
    }
  },

  /**
   * Add an apt repository source, either as a PPA or a custom source line.
   *
   * **PPA form**: pass `"ppa:user/name"` as the first argument (no `source`).
   * Uses `add-apt-repository` internally.
   *
   * **Standard form**: pass a name and a deb source line. The source is
   * written to `/etc/apt/sources.list.d/<name>.list`. The `signed-by` option
   * is automatically derived from `name` (pointing to
   * `/etc/apt/keyrings/<name>.gpg`) unless overridden.
   *
   * @param nameOrPpa - Repository name or PPA identifier (e.g. `"ppa:user/name"`).
   * @param source - The deb source line (omit for PPA form).
   * @param options - Optional settings.
   * @param options.signedBy - Override the key name used for `signed-by`
   *   (`false` to disable auto-derivation, a string to use a different key name).
   * @returns A Module that configures the repository.
   *
   * @example
   * // PPA form
   * apt.repository("ppa:ondrej/php")
   *
   * @example
   * // Standard form – signed-by is auto-derived from "nodejs"
   * apt.repository(
   *   "nodejs",
   *   "deb https://deb.nodesource.com/node_20.x nodistro main",
   * )
   *
   * @example
   * // Standard form with signed-by disabled
   * apt.repository(
   *   "internal",
   *   "deb [arch=amd64] https://packages.example.com stable main",
   *   { signedBy: false },
   * )
   */
  repository(nameOrPpa: string, source?: string, options?: { signedBy?: false | string }): Module {
    if (nameOrPpa.startsWith(PPA_PREFIX) && source === undefined) {
      return buildPpaRepository(nameOrPpa)
    }

    if (source === undefined) {
      throw new Error("apt.repository: source is required for non-PPA repositories")
    }

    const name = nameOrPpa
    validateAptResourceName(name)
    const signedBy = options?.signedBy
    let expectedContent = validateRepositorySourceLine(source)

    if (signedBy !== false) {
      const keyName = typeof signedBy === "string" ? signedBy : name
      validateAptResourceName(keyName)
      expectedContent = injectSignedBy(expectedContent, `/etc/apt/keyrings/${keyName}.gpg`)
    }

    const filePath = `/etc/apt/sources.list.d/${name}.list`
    const updateFlag = buildRepositoryUpdateFlag(name, expectedContent)

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[apt.repository] SSH connection is required for ${name}`)
        // R-0000235: refuse to write through a symlinked sources.list file.
        // `writeFile` follows symlinks and would mutate whatever the link
        // target points at. Mirrors the apt.key (R-0000134) and
        // compose.systemd (R-0000192) hardening.
        //
        // R-0000531: this `isSymlink` check is a fail-fast guard only; it is
        // intentionally racy on its own. The atomic write guarantee comes
        // from `ssh.writeFile` itself, which routes through
        // `finalizeRemoteTempFile` (mktemp -> SFTP stream -> chmod -> chown
        // -> `mv -T -- temp final`) with an in-shell guard
        // `[ ! -d final ] && [ ! -L final ]` evaluated in the same shell
        // invocation as the final `mv -T`. A symlink swap between this
        // pre-check and the final `mv` is therefore detected by the
        // in-shell guard, which aborts before the rename. The pre-check
        // exists so the operator sees a clean
        // `apt.repository refuses to write through symlink` diagnostic for
        // the common (non-adversarial) case where a stale symlink is left
        // behind, instead of the lower-level finalize error.
        if (await isSymlink(ssh, filePath)) {
          return failed(`[apt.repository] refuses to write through symlink at ${filePath}`)
        }
        const previousRepository = await snapshotAptRepository(ssh, filePath)
        // R-0000566: close the read/write race window. If the sources.list
        // changed on disk between `snapshotAptRepository` (the readFile
        // above) and this point, a later rollback would restore the wrong
        // (older) content. Verify the on-disk SHA-256 matches the snapshot
        // before writing; on mismatch abort apply *before* `apt-get update`
        // runs so the operator can re-run after investigating.
        const integrityFailure = await ensureAptRepositorySnapshotStillCurrent({
          filePath,
          name,
          snapshot: previousRepository,
          ssh,
        })
        if (integrityFailure) return integrityFailure
        // R-0000753: capture the exact bytes written so the rollback path
        // can refuse to overwrite a sources.list that has drifted in the
        // apt-get-update failure window.
        const appliedContent = `${expectedContent}\n`
        await ssh.writeFile(filePath, appliedContent, { mode: APT_REPOSITORY_MODE })
        const result = await ssh.exec(`${NONINTERACTIVE} apt-get update`, {
          ignoreExitCode: true,
          silent: true,
        })
        if (result.code !== 0) {
          return rollbackRepositoryAfterUpdateFailure({
            appliedContent,
            filePath,
            name,
            previousRepository,
            ssh,
            updateResult: result,
          })
        }
        // R-0000273: surface flag-persist failures (EROFS/EPERM/ENOSPC)
        // through the failedCommand path rather than letting the helper
        // throw after a successful apt-get update.
        const flagFailure = await setVersionedFlag(ssh, updateFlag.flagName, updateFlag.flagPrefix)
        if (flagFailure) return flagFailure
        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        // R-0000235: a symlink at the sources.list path is treated as "not
        // present" so apply runs, where it will refuse the write with a clear
        // error. The combined test prevents `[ -f path ]` from following a
        // symlink and reporting a stale or attacker-controlled target as
        // up-to-date. Mirrors the apt.key (R-0000134) hardening.
        const exists = await ssh.test(
          `[ -f ${shellQuote(filePath)} ] && [ ! -L ${shellQuote(filePath)} ]`
        )
        if (!exists) return NEEDS_APPLY
        const content = await ssh.readFile(filePath)
        // R-0000051: tolerate whitespace-only drift (tabs vs. spaces,
        // collapsed vs. multiple spaces, trailing whitespace) by
        // normalizing consecutive whitespace to a single space and
        // trimming both sides before comparing. The deb source-line
        // grammar treats any whitespace as a field separator, so
        // `deb<TAB>https://...` and `deb https://...` are semantically
        // identical and must not flap between `ok` and `needs-apply`.
        if (normalizeAptSourceContent(content) !== normalizeAptSourceContent(expectedContent)) {
          return NEEDS_APPLY
        }

        // R-0000558: use ssh.exec with ignoreExitCode so a transient stat
        // failure (file removed between the symlink probe and the mode read,
        // EACCES, EIO, …) becomes NEEDS_APPLY instead of throwing a raw
        // CommandError out of check. Mirrors the crontab/R-0000272 pattern.
        const modeResult = await ssh.exec(
          `stat -c '%a' ${shellQuote(filePath)}`,
          APT_BASE_EXEC_OPTS
        )
        if (modeResult.code !== 0) return NEEDS_APPLY
        if (modeResult.stdout.trim() !== APT_REPOSITORY_MODE.replace(/^0+/v, "")) {
          return NEEDS_APPLY
        }

        return (await hasFlag(ssh, updateFlag.flagName)) ? "ok" : NEEDS_APPLY
      },
      name: `apt.repository: ${name}`,
    }
  },
}

/**
 * Normalize an apt source-list file content so superficial whitespace
 * differences (tabs vs. spaces, collapsed runs, trailing whitespace) do
 * not cause spurious drift. Each non-empty, non-comment line is collapsed
 * to a single-space-separated form.
 *
 * @param content - The raw file content as read from disk.
 * @returns The normalized comparison form.
 */
function normalizeAptSourceContent(content: string): string {
  return content
    .split(/\r?\n/v)
    .map((line) => line.replaceAll(/\s+/gv, " ").trim())
    .filter((line) => line.length > 0)
    .join("\n")
}
