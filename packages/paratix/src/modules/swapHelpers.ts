import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import {
  classifySwapFilePath,
  ensureSwapFilePresent,
  ensureSwapFstabState,
  hasNoSwapFstabEntry,
  hasSwapFstabEntry,
  isSwapActive,
  needsSwapRecreation,
  type NormalizedSwapFileOptions,
  swapFileModeMatches,
} from "./swapFileHelpers.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

async function ensureSafeSwapRemoval(
  ssh: SshConnection,
  path: string
): Promise<"missing" | "ok" | ModuleResult> {
  const classification = await classifySwapFilePath(ssh, path)
  if (classification.state === "missing") return "missing"
  if (classification.state === "managed-swap-file") return "ok"
  return failed(`[swap.file: ${path}] refusing to remove unsafe path: ${classification.reason}`)
}

async function disableSwap(ssh: SshConnection, path: string): Promise<boolean | ModuleResult> {
  if (!(await isSwapActive(ssh, path))) return false
  const result = await ssh.exec(`swapoff ${shellQuote(path)}`, EXEC_OPTS)
  return result.code === 0 ? true : failedCommand(`[swap.file: ${path}] swapoff failed`, result)
}

async function removeSwapFile(ssh: SshConnection, path: string): Promise<boolean | ModuleResult> {
  if (!(await ssh.exists(path))) return false
  const result = await ssh.exec(`rm -f ${shellQuote(path)}`, EXEC_OPTS)
  return result.code === 0 ? true : failedCommand(`[swap.file: ${path}] rm failed`, result)
}

async function recreateSwapFile(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<"changed" | "ok" | ModuleResult> {
  if (!(await needsSwapRecreation(ssh, options))) return "ok"

  const safeRemoval = await ensureSafeSwapRemoval(ssh, options.path)
  if (typeof safeRemoval !== "string") return safeRemoval

  const disableResult = await disableSwap(ssh, options.path)
  if (typeof disableResult !== "boolean") return disableResult

  if (safeRemoval === "ok") {
    const removeResult = await removeSwapFile(ssh, options.path)
    if (typeof removeResult !== "boolean") return removeResult
  }

  const createResult = await ensureSwapFilePresent({
    mode: options.mode,
    path: options.path,
    size: options.sizeForCommand,
    sizeBytes: options.sizeBytes,
    ssh,
  })
  return createResult === true ? "changed" : createResult
}

async function enableSwap(ssh: SshConnection, path: string): Promise<boolean | ModuleResult> {
  if (await isSwapActive(ssh, path)) return false
  const result = await ssh.exec(`swapon ${shellQuote(path)}`, EXEC_OPTS)
  return result.code === 0 ? true : failedCommand(`[swap.file: ${path}] swapon failed`, result)
}

async function applyAbsentSwapFile(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<ModuleResult> {
  let swapChanged = false
  const safeRemoval = await ensureSafeSwapRemoval(ssh, options.path)
  if (typeof safeRemoval !== "string") return safeRemoval
  const disableResult = await disableSwap(ssh, options.path)
  if (typeof disableResult !== "boolean") return disableResult
  if (disableResult) swapChanged = true
  if (await ensureSwapFstabState({ desiredLine: null, path: options.path, ssh })) swapChanged = true
  if (safeRemoval === "ok") {
    const removeResult = await removeSwapFile(ssh, options.path)
    if (typeof removeResult !== "boolean") return removeResult
    if (removeResult) swapChanged = true
  }
  return { status: swapChanged ? "changed" : "ok" }
}

async function applyPresentSwapFile(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<ModuleResult> {
  let swapChanged = false
  const recreateResult = await recreateSwapFile(ssh, options)
  if (typeof recreateResult !== "string") return recreateResult
  if (recreateResult === "changed") swapChanged = true
  const enableResult = await enableSwap(ssh, options.path)
  if (typeof enableResult !== "boolean") return enableResult
  if (enableResult) swapChanged = true
  if (
    await ensureSwapFstabState({ desiredLine: options.expectedFstabLine, path: options.path, ssh })
  ) {
    swapChanged = true
  }
  return { status: swapChanged ? "changed" : "ok" }
}

export async function applySwapFile(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<ModuleResult> {
  return options.state === "absent"
    ? applyAbsentSwapFile(ssh, options)
    : applyPresentSwapFile(ssh, options)
}

async function checkAbsent(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<"needs-apply" | "ok"> {
  if (await ssh.exists(options.path)) return NEEDS_APPLY
  if (await isSwapActive(ssh, options.path)) return NEEDS_APPLY
  return (await hasNoSwapFstabEntry(ssh, options.path)) ? "ok" : NEEDS_APPLY
}

async function checkPresent(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<"needs-apply" | "ok"> {
  if (await needsSwapRecreation(ssh, options)) return NEEDS_APPLY
  if (!(await isSwapActive(ssh, options.path))) return NEEDS_APPLY
  if (!(await hasSwapFstabEntry(ssh, options))) return NEEDS_APPLY
  return (await swapFileModeMatches(ssh, options)) ? "ok" : NEEDS_APPLY
}

export async function checkSwapFile(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<"needs-apply" | "ok"> {
  return options.state === "absent" ? checkAbsent(ssh, options) : checkPresent(ssh, options)
}
