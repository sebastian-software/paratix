import { posix as posixPath } from "node:path"

import type { ModuleResult, SshConnection } from "../types.js"
import type { NormalizedSwapFileOptions, SwapFilePathClassification } from "./swapFileTypes.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote, validateMode } from "../ssh.js"

export {
  cleanupSwapTemporaryFile,
  createInitializedSwapTemporaryFile,
  ensureSwapFilePresent,
  publishInitializedSwapTemporaryFile,
} from "./swapFileCreateHelpers.js"
export type { NormalizedSwapFileOptions, SwapFilePathClassification } from "./swapFileTypes.js"
export { ensureSwapFstabState, hasNoSwapFstabEntry, hasSwapFstabEntry } from "./swapFstabHelpers.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const KIBI = 1024
const POWER_0 = 0
const POWER_1 = 1
const POWER_2 = 2
const POWER_3 = 3
const POWER_4 = 4
const POWER_5 = 5
const SIZE_POWERS = {
  "": POWER_0,
  G: POWER_3,
  K: POWER_1,
  M: POWER_2,
  P: POWER_5,
  T: POWER_4,
} as const
const MIN_SWAP_PRIORITY = -1
const MAX_SWAP_PRIORITY = 32_767

function isSizeUnit(unit: string): unit is keyof typeof SIZE_POWERS {
  return Object.hasOwn(SIZE_POWERS, unit)
}

function parseSizeString(size: string): { unit: keyof typeof SIZE_POWERS; value: string } {
  const match = /^(?<value>\d+)(?<unit>[KMGTP]?)$/iv.exec(size.trim())
  if (match?.groups == null) {
    throw new Error(`swap.file: unsupported size format "${size}"`)
  }
  const unit = match.groups.unit.toUpperCase()
  if (!isSizeUnit(unit)) {
    throw new Error(`swap.file: unsupported size unit "${unit}"`)
  }
  return { unit, value: match.groups.value }
}

function safeIntegerBytes(
  valueBig: bigint,
  unit: keyof typeof SIZE_POWERS,
  original: string
): number {
  // R-0000178: compute the byte count via BigInt so very large units (T/P)
  // do not silently overflow `Number.MAX_SAFE_INTEGER`. Reject values that
  // would not survive the round-trip back to a safe integer.
  const factor = BigInt(KIBI) ** BigInt(SIZE_POWERS[unit])
  const bytesBig = valueBig * factor
  if (bytesBig > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(
      `swap.file: size "${original}" exceeds Number.MAX_SAFE_INTEGER (${String(Number.MAX_SAFE_INTEGER)} bytes)`
    )
  }
  return Number(bytesBig)
}

function normalizeSizeToBytes(size: number | string): number {
  if (typeof size === "number") {
    if (!Number.isInteger(size) || size <= 0) {
      throw new Error("swap.file: numeric size must be a positive integer byte count")
    }
    return size
  }

  const { unit, value } = parseSizeString(size)
  return safeIntegerBytes(BigInt(value), unit, size)
}

function normalizeSizeForCommand(size: number | string): string {
  return typeof size === "number" ? String(size) : size.trim()
}

function buildSwapFstabLine(path: string, priority?: number): string {
  const options = priority == null ? "sw" : `sw,pri=${String(priority)}`
  return `${path} none swap ${options} 0 0`
}

function validateSwapFilePath(value: string): void {
  if (value === "") {
    throw new Error("swap.file: path must be a non-empty absolute path")
  }
  if (/\s/v.test(value)) {
    throw new Error("swap.file: path must not contain whitespace")
  }
  if (!posixPath.isAbsolute(value)) {
    throw new Error("swap.file: path must be absolute")
  }
  if (value === "/") {
    throw new Error("swap.file: path must not be the filesystem root")
  }
  if (posixPath.normalize(value) !== value) {
    throw new Error("swap.file: path must be normalized")
  }
}

function validateSwapPriority(priority: number | undefined): void {
  if (priority === undefined) return
  if (!Number.isInteger(priority) || priority < MIN_SWAP_PRIORITY || priority > MAX_SWAP_PRIORITY) {
    throw new Error(
      `swap.file: priority must be an integer between ${MIN_SWAP_PRIORITY} and ${MAX_SWAP_PRIORITY}`
    )
  }
}

function validateSwapFileState(state: unknown): asserts state is "absent" | "present" {
  if (state !== "present" && state !== "absent") {
    throw new Error('swap.file state must be "present" or "absent"')
  }
}

export async function isSwapActive(ssh: SshConnection, path: string): Promise<boolean> {
  const activeSwaps = await ssh.lines("swapon --show=NAME --noheadings")
  return activeSwaps.some((line) => line.trim() === path)
}

async function hasSwapSignature(ssh: SshConnection, path: string): Promise<boolean> {
  return ssh.test(`swaplabel ${shellQuote(path)} >/dev/null 2>&1`)
}

// R-0000648: route stat through `ssh.exec(..., { ignoreExitCode: true })`
// instead of `ssh.output`, which throws on a non-zero exit. A TOCTOU race
// (the file is unlinked between `ssh.exists` and `stat`) or a permission
// error must surface as a structured failure so callers can convert it to
// NEEDS_APPLY (check path) or a failed ModuleResult (apply path) without
// the rest of the module crashing with an unstructured exception.
async function readFileSizeInBytes(
  ssh: SshConnection,
  path: string
): Promise<ModuleResult | number> {
  const result = await ssh.exec(`stat -c %s ${shellQuote(path)}`, EXEC_OPTS)
  if (result.code !== 0) {
    return failedCommand(`[swap.file: ${path}] stat failed while reading swap file size`, result)
  }
  const parsed = Number.parseInt(result.stdout.trim(), 10)
  if (!Number.isFinite(parsed)) {
    return failed(
      `[swap.file: ${path}] stat returned a non-numeric size: ${JSON.stringify(result.stdout)}`
    )
  }
  return parsed
}

export async function classifySwapFilePath(
  ssh: SshConnection,
  path: string
): Promise<SwapFilePathClassification> {
  if (await ssh.test(`[ -L ${shellQuote(path)} ]`)) {
    return { reason: "existing path is a symbolic link", state: "unsafe" }
  }
  if (!(await ssh.exists(path))) return { state: "missing" }
  if (!(await ssh.test(`[ -f ${shellQuote(path)} ]`))) {
    return { reason: "existing path is not a regular file", state: "unsafe" }
  }
  if (!(await hasSwapSignature(ssh, path))) {
    return { reason: "existing regular file is not a swap file", state: "unsafe" }
  }
  return { state: "managed-swap-file" }
}

export function normalizeSwapFileOptions(options: {
  mode?: string
  path: string
  priority?: number
  size: number | string
  state?: "absent" | "present"
}): NormalizedSwapFileOptions {
  if (options.state !== undefined) validateSwapFileState(options.state)
  const state = options.state ?? "present"
  const mode = options.mode ?? "0600"
  validateSwapFilePath(options.path)
  validateMode(mode)
  validateSwapPriority(options.priority)
  return {
    expectedFstabLine:
      state === "present" ? buildSwapFstabLine(options.path, options.priority) : null,
    mode,
    path: options.path,
    sizeBytes: normalizeSizeToBytes(options.size),
    sizeForCommand: normalizeSizeForCommand(options.size),
    state,
  }
}

// R-0000648: `needsSwapRecreation` may now report a structured failure when
// the underlying `stat` call fails after `ssh.exists` reported the path as
// present (typical TOCTOU symptom). Callers translate this failure into
// NEEDS_APPLY on the check path and into a failed ModuleResult on the
// apply path.
export async function needsSwapRecreation(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<boolean | ModuleResult> {
  if (!(await ssh.exists(options.path))) return true
  const sizeResult = await readFileSizeInBytes(ssh, options.path)
  if (typeof sizeResult !== "number") return sizeResult
  if (sizeResult !== options.sizeBytes) return true
  return !(await hasSwapSignature(ssh, options.path))
}

function normalizeMode(mode: string): string {
  return mode.replace(/^0+/v, "")
}

// R-0000681: surface soft failures from the `stat` probe instead of folding
// every non-zero exit into a plain `false`. Without this distinction
// `checkPresent` cannot tell a permission denial or TOCTOU race apart from a
// genuine mode mismatch, and `ensureSwapFileMode` would silently retry the
// chmod whenever stat hit a transient error. The return shape mirrors
// `needsSwapRecreation`: `boolean` for the converged answer, `ModuleResult`
// for a structured failure that callers translate to NEEDS_APPLY (check)
// or propagate as failed (apply).
export async function swapFileModeMatches(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<boolean | ModuleResult> {
  const result = await ssh.exec(`stat -c '%a' ${shellQuote(options.path)}`, EXEC_OPTS)
  if (result.code !== 0) {
    return failedCommand(`[swap.file: ${options.path}] stat failed while reading swap file mode`, result)
  }
  const currentMode = result.stdout.trim()
  if (currentMode === "") {
    return failed(
      `[swap.file: ${options.path}] stat returned an empty mode for ${options.path}`
    )
  }
  return normalizeMode(currentMode) === normalizeMode(options.mode)
}

export async function ensureSwapFileMode(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<boolean | ModuleResult> {
  // R-0000681: propagate a soft `stat` failure from `swapFileModeMatches` as
  // a structured ModuleResult instead of retrying the chmod on a stale
  // assumption that the mode mismatched.
  const matches = await swapFileModeMatches(ssh, options)
  if (typeof matches !== "boolean") return matches
  if (matches) return false
  const result = await ssh.exec(
    `chmod ${shellQuote(options.mode)} ${shellQuote(options.path)}`,
    EXEC_OPTS
  )
  return result.code === 0
    ? true
    : failedCommand(`[swap.file: ${options.path}] chmod failed`, result)
}
