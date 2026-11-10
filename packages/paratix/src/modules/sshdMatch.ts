import type { SshdConfigTransaction } from "./sshd.js"

import { failed } from "../moduleFailure.js"
import { shellQuote, validateMktempPath } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { certificateCommand, certificateFileMatches } from "./sshCertificateFiles.js"
import { CertificateFilesTransaction } from "./sshCertificateFileTransaction.js"
import { withSshdConfigTransaction } from "./sshd.js"
import { readStagedSshdConfig, stageSshdConfigTree } from "./sshdIncludeStaging.js"
import {
  clearActivationPending,
  readActivationPending,
  recordActivationPending,
} from "./sshdMatchActivation.js"
import {
  assertConnectionUserUnmatched,
  assertEffective,
  type DropIn,
  errorText,
  inspectDropIn,
  readMainConfig,
  SSHD_CONFIG,
  SshdMatchError,
  type VerifyUserPending,
  verifyUserPending,
  verifyUserPendingText,
} from "./sshdMatchChecks.js"
import {
  buildSshdMatchSpec,
  type SshdMatchCriteria,
  type SshdMatchDirectives,
  type SshdMatchOptions,
  type SshdMatchSpec,
} from "./sshdMatchSpec.js"

export type { SshdMatchCriteria, SshdMatchDirectives, SshdMatchOptions } from "./sshdMatchSpec.js"

const STAGING_PREFIX = "paratix-sshd-match"
const PRIVILEGE_SEPARATION_SKIP =
  "(dry-run skipped: /run/sshd missing — sshd -t cannot run without the " +
  "privilege-separation directory; not creating it from a dry-run)"

type Mode = "apply" | "check" | "dry-run"
type Target = { mode: Mode; spec: SshdMatchSpec; transaction: SshdConfigTransaction }
/** `activationPending`: an earlier run changed the drop-in without a confirmed reload. */
type Context = { activationPending: boolean } & Target

// Returns the cleanup failure instead of throwing, so it never hides a body error.
async function removeStagingDirectory(
  ssh: SshConnection,
  directory: string
): Promise<string | undefined> {
  try {
    await certificateCommand(ssh, `rm -rf -- ${shellQuote(directory)}`)
    return undefined
  } catch (error) {
    return `${directory}: ${errorText(error)}`
  }
}

async function withStagingDirectory<T>(
  ssh: SshConnection,
  body: (directory: string) => Promise<T>
): Promise<T> {
  const directory = validateMktempPath(
    "/tmp",
    await certificateCommand(ssh, `mktemp -d -p /tmp -- '${STAGING_PREFIX}.XXXXXX'`),
    STAGING_PREFIX
  )
  let result: T
  try {
    result = await body(directory)
  } catch (error) {
    const failure = await removeStagingDirectory(ssh, directory)
    if (failure === undefined) throw error
    throw new SshdMatchError(`${errorText(error)}; staging cleanup also failed: ${failure}`, {
      cause: error,
    })
  }
  const cleanupFailure = await removeStagingDirectory(ssh, directory)
  if (cleanupFailure !== undefined)
    throw new SshdMatchError(`staging cleanup failed: ${cleanupFailure}`)
  return result
}

// Stage the full Include tree with (or without) the candidate and validate it.
async function validateCandidate(
  context: Context,
  input: { mainContent: string; user?: string }
): Promise<void> {
  const ssh = context.transaction.connection
  const { spec } = context
  await withStagingDirectory(ssh, async (directory) => {
    const path = await stageSshdConfigTree(ssh, {
      content: input.mainContent,
      directory,
      includeOverride: {
        content: spec.state === "present" ? spec.content : null,
        path: spec.path,
      },
      rootPath: SSHD_CONFIG,
    })
    const output = await readStagedSshdConfig(ssh, { path, user: input.user })
    if (input.user !== undefined) assertEffective(output, spec, "the staged sshd -T -C")
  })
}

async function rollback(
  context: Context,
  files: CertificateFilesTransaction,
  parameters: { error: unknown; reloadAttempted: boolean }
): Promise<ModuleResult> {
  const failures = await files.rollback()
  if (parameters.reloadAttempted) {
    try {
      await context.transaction.restoreReload()
    } catch (restoreError) {
      failures.push(`live sshd configuration: ${String(restoreError)}`)
    }
  }
  const { activationPending, spec, transaction } = context
  // A marker from an earlier run protects an activation whose daemon state is still
  // unknown; after an incomplete rollback the disk and the daemon may disagree.
  if (!activationPending && failures.length === 0) {
    const clearFailure = await clearActivationPending(transaction.connection, spec)
    if (clearFailure !== undefined) failures.push(`${spec.pendingPath}: ${clearFailure}`)
  }
  const restored =
    failures.length === 0
      ? "; previous drop-in state restored"
      : `; rollback also failed: ${failures.join("; ")}`
  const pending =
    activationPending || failures.length > 0
      ? `; activation of ${spec.path} stays pending for the next apply`
      : ""
  return failed(`[${spec.moduleName}] ${errorText(parameters.error)}${restored}${pending}`)
}

async function mutate(
  context: Context,
  files: CertificateFilesTransaction,
  dropIn: DropIn
): Promise<void> {
  const { spec, transaction } = context
  if (spec.state === "present") {
    await files.write(dropIn)
    // sshd -T reads the published files, not the running daemon: verify before reloading.
    assertEffective(await transaction.readEffectiveOutput(spec.verifyUser), spec, "sshd -T -C")
  } else {
    await files.remove(dropIn)
    await transaction.readEffectiveOutput()
  }
}

function publishedDetail(spec: SshdMatchSpec, dropIn: DropIn): string {
  // Only a pending activation reaches publish with the file already converged.
  if (certificateFileMatches(dropIn)) return `activated pending change for ${spec.path}`
  return spec.state === "present" ? `wrote ${spec.path}` : `removed ${spec.path}`
}

// Runs only after a confirmed reload, so it reports failures without implying a rollback.
async function finishPublish(
  context: Context,
  files: CertificateFilesTransaction,
  dropIn: DropIn
): Promise<ModuleResult> {
  const { spec, transaction } = context
  const done = publishedDetail(spec, dropIn)
  const clearFailure = await clearActivationPending(transaction.connection, spec)
  const cleanup = await files.cleanup()
  const problems = [
    ...(clearFailure === undefined
      ? []
      : [`${spec.pendingPath} remains and a later run reloads once more: ${clearFailure}`]),
    ...(cleanup.length > 0 ? [`temporary-file cleanup failed: ${cleanup.join("; ")}`] : []),
  ]
  if (problems.length > 0)
    return failed(`[${spec.moduleName}] ${done} and reloaded sshd; ${problems.join("; ")}`)
  return { detail: done, status: "changed" }
}

async function publish(context: Context, dropIn: DropIn): Promise<ModuleResult> {
  const { activationPending, spec, transaction } = context
  await transaction.requireReloadOnly()
  if (!activationPending) await recordActivationPending(transaction.connection, spec)
  const files = new CertificateFilesTransaction(transaction.connection)
  let reloadAttempted = false
  try {
    await mutate(context, files, dropIn)
    reloadAttempted = true
    await transaction.reloadOnly()
  } catch (error) {
    return rollback(context, files, { error, reloadAttempted })
  }
  return finishPublish(context, files, dropIn)
}

type Pending = Exclude<VerifyUserPending, undefined>

function pendingDetail(spec: SshdMatchSpec, pending: Pending, prefix: string): string {
  return `(${prefix}; effect check pending: ${verifyUserPendingText(spec, pending)} yet)`
}

// Resolves whether the effect check can run. Apply fails for a missing verify
// user or group membership; check and dry-run defer both, because the same run
// may still create the account or add the membership before apply.
async function resolveEffectCheck(context: Context): Promise<Pending | undefined> {
  const { mode, spec, transaction } = context
  const pending = await verifyUserPending(transaction.connection, spec)
  if (pending !== undefined && mode === "apply")
    throw new SshdMatchError(verifyUserPendingText(spec, pending))
  return pending
}

async function verifyConverged(context: Context): Promise<ModuleResult> {
  const { mode, spec, transaction } = context
  if (spec.state === "absent") return { status: "ok" }
  if (!(await transaction.preparePrivilegeSeparation()))
    return mode === "check"
      ? { status: "changed" }
      : { _dryRunDetail: PRIVILEGE_SEPARATION_SKIP, status: "skipped" }
  const pending = await resolveEffectCheck(context)
  if (pending !== undefined)
    return { _dryRunDetail: pendingDetail(spec, pending, "dry-run"), status: "changed" }
  assertEffective(await transaction.readEffectiveOutput(spec.verifyUser), spec, "sshd -T -C")
  return { status: "ok" }
}

// Runs the lockout guard, then resolves whether the effect check can run.
async function prepareConverge(context: Context): Promise<"absent" | Pending | undefined> {
  await assertConnectionUserUnmatched(context.transaction.connection, context.spec)
  if (context.spec.state === "absent") return "absent"
  return resolveEffectCheck(context)
}

async function converge(
  context: Context,
  dropIn: DropIn,
  mainContent: string
): Promise<ModuleResult> {
  const { mode, spec, transaction } = context
  const pending = await prepareConverge(context)
  if (mode === "check") return { status: "changed" }
  if (!(await transaction.preparePrivilegeSeparation()))
    return { _dryRunDetail: PRIVILEGE_SEPARATION_SKIP, status: "skipped" }
  await validateCandidate(context, {
    mainContent,
    user: pending === undefined ? spec.verifyUser : undefined,
  })
  if (mode === "apply") return publish(context, dropIn)
  // Read-only (systemctl show / is-active): apply would refuse without a pure reload.
  await transaction.requireReloadOnly()
  const notDone = certificateFileMatches(dropIn)
    ? "activation pending from an earlier run"
    : "drop-in not written"
  return {
    _dryRunDetail:
      pending === undefined || pending === "absent"
        ? `(dry-run, staged sshd -t/-T ok; ${notDone}, reload not executed)`
        : pendingDetail(spec, pending, "dry-run, sshd -t ok"),
    status: "changed",
  }
}

async function section(target: Target): Promise<ModuleResult> {
  const ssh = target.transaction.connection
  const mainContent = await readMainConfig(ssh, target.spec)
  const dropIn = await inspectDropIn(ssh, target.spec)
  const activationPending = await readActivationPending(ssh, target.spec)
  const context: Context = { ...target, activationPending }
  const fileConverged =
    target.spec.state === "present" ? certificateFileMatches(dropIn) : dropIn.original === null
  // sshd -T reads the disk, so only a reload can settle a pending activation.
  if (fileConverged && !activationPending) return verifyConverged(context)
  return converge(context, dropIn, mainContent)
}

async function runMatch(
  ssh: null | SshConnection,
  spec: SshdMatchSpec,
  mode: Mode
): Promise<ModuleResult> {
  if (ssh === null) return failed(`[${spec.moduleName}] SSH connection is required`)
  try {
    return await withSshdConfigTransaction(ssh, {
      dryRun: mode !== "apply",
      name: spec.moduleName,
      section: async (transaction) => section({ mode, spec, transaction }),
    })
  } catch (error) {
    return failed(`[${spec.moduleName}] ${errorText(error)}`)
  }
}

/**
 * Build the `sshd.match` module; see `sshd.match` for the public contract.
 * @param name - Drop-in name.
 * @param criteria - Literal user and/or group criteria.
 * @param input - Directives and options.
 * @param input.directives - Allowlisted directives.
 * @param input.options - State, verification user and lockout override.
 * @returns The module managing `/etc/ssh/sshd_config.d/<name>.conf`.
 */
export function sshdMatchModule(
  name: string,
  criteria: SshdMatchCriteria,
  input: { directives: SshdMatchDirectives; options: SshdMatchOptions }
): Module {
  const spec = buildSshdMatchSpec(name, criteria, input)
  return {
    async _applyDryRun(ssh) {
      return runMatch(ssh, spec, "dry-run")
    },
    async apply(ssh) {
      return runMatch(ssh, spec, "apply")
    },
    async check(ssh) {
      if (ssh === null) return NEEDS_APPLY
      const result = await runMatch(ssh, spec, "check")
      if (result.status === "failed")
        process.stderr.write(`Warning: ${result.error?.message ?? spec.moduleName}\n`)
      return result.status === "ok" ? "ok" : NEEDS_APPLY
    },
    name: spec.moduleName,
  }
}
