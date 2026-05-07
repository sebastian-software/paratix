import { posix as posixPath } from "node:path"

import { failedCommand } from "../moduleFailure.js"
import { shellQuote, validateMode } from "../ssh.js"
import { guardedWriteFile, type ModuleResult, type SshConnection } from "../types.js"

export {
  cleanupSwapTemporaryFile,
  createInitializedSwapTemporaryFile,
  ensureSwapFilePresent,
  publishInitializedSwapTemporaryFile,
} from "./swapFileCreateHelpers.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const FSTAB_PATH = "/etc/fstab"
const FSTAB_MODE = "0644"
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

export type NormalizedSwapFileOptions = {
  expectedFstabLine: null | string
  mode: string
  path: string
  sizeBytes: number
  sizeForCommand: string
  state: "absent" | "present"
}

export type SwapFilePathClassification =
  | { reason: string; state: "unsafe" }
  | { state: "managed-swap-file" }
  | { state: "missing" }

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

function findFstabEntry(fstabContent: string, path: string): null | string {
  for (const line of fstabContent.split("\n")) {
    const trimmed = line.trim()
    if (trimmed === "" || trimmed.startsWith("#")) continue
    const fields = trimmed.split(/\s+/v)
    if (fields[0] === path) return trimmed
  }
  return null
}

function upsertFstabEntry(fstabContent: string, path: string, newLine: string): string {
  const lines = fstabContent.split("\n")
  const index = lines.findIndex((line) => {
    const trimmed = line.trim()
    if (trimmed === "" || trimmed.startsWith("#")) return false
    const fields = trimmed.split(/\s+/v)
    return fields[0] === path
  })

  if (index === -1) {
    while (lines.length > 0 && lines.at(-1)?.trim() === "") {
      lines.pop()
    }
    lines.push(newLine)
  } else {
    lines[index] = newLine
  }

  return `${lines.join("\n")}\n`
}

function removeFstabEntry(fstabContent: string, path: string): string {
  const lines = fstabContent.split("\n")
  const result = lines.filter((line) => {
    const trimmed = line.trim()
    if (trimmed === "" || trimmed.startsWith("#")) return true
    const fields = trimmed.split(/\s+/v)
    return fields[0] !== path
  })
  return `${result.join("\n")}\n`
}

export async function isSwapActive(ssh: SshConnection, path: string): Promise<boolean> {
  const activeSwaps = await ssh.lines("swapon --show=NAME --noheadings")
  return activeSwaps.some((line) => line.trim() === path)
}

async function hasSwapSignature(ssh: SshConnection, path: string): Promise<boolean> {
  return ssh.test(`swaplabel ${shellQuote(path)} >/dev/null 2>&1`)
}

async function readFileSizeInBytes(ssh: SshConnection, path: string): Promise<number> {
  const output = await ssh.output(`stat -c %s ${shellQuote(path)}`)
  return Number.parseInt(output.trim(), 10)
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

export async function ensureSwapFstabState(parameters: {
  desiredLine: null | string
  path: string
  ssh: SshConnection
}): Promise<boolean> {
  const fstabContent = await parameters.ssh.readFile(FSTAB_PATH)
  const currentEntry = findFstabEntry(fstabContent, parameters.path)

  if (parameters.desiredLine == null) {
    if (currentEntry == null) return false
    const removedContent = removeFstabEntry(fstabContent, parameters.path)
    await guardedWriteFile(parameters.ssh, {
      mode: FSTAB_MODE,
      newContent: removedContent,
      originalContent: fstabContent,
      remotePath: FSTAB_PATH,
    })
    return true
  }

  if (currentEntry === parameters.desiredLine) return false
  const updatedContent = upsertFstabEntry(fstabContent, parameters.path, parameters.desiredLine)
  await guardedWriteFile(parameters.ssh, {
    mode: FSTAB_MODE,
    newContent: updatedContent,
    originalContent: fstabContent,
    remotePath: FSTAB_PATH,
  })
  return true
}

export function normalizeSwapFileOptions(options: {
  mode?: string
  path: string
  priority?: number
  size: number | string
  state?: "absent" | "present"
}): NormalizedSwapFileOptions {
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

export async function needsSwapRecreation(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<boolean> {
  if (!(await ssh.exists(options.path))) return true
  if ((await readFileSizeInBytes(ssh, options.path)) !== options.sizeBytes) return true
  return !(await hasSwapSignature(ssh, options.path))
}

export async function hasSwapFstabEntry(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<boolean> {
  const currentFstabContent = await ssh.readFile(FSTAB_PATH)
  return findFstabEntry(currentFstabContent, options.path) === options.expectedFstabLine
}

export async function hasNoSwapFstabEntry(ssh: SshConnection, path: string): Promise<boolean> {
  const currentFstabContent = await ssh.readFile(FSTAB_PATH)
  return findFstabEntry(currentFstabContent, path) == null
}

function normalizeMode(mode: string): string {
  return mode.replace(/^0+/v, "")
}

export async function swapFileModeMatches(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<boolean> {
  const result = await ssh.exec(`stat -c '%a' ${shellQuote(options.path)}`, EXEC_OPTS)
  if (result.code !== 0) return false
  const currentMode = result.stdout.trim()
  if (currentMode === "") return false
  return normalizeMode(currentMode) === normalizeMode(options.mode)
}

export async function ensureSwapFileMode(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<boolean | ModuleResult> {
  if (await swapFileModeMatches(ssh, options)) return false
  const result = await ssh.exec(
    `chmod ${shellQuote(options.mode)} ${shellQuote(options.path)}`,
    EXEC_OPTS
  )
  return result.code === 0
    ? true
    : failedCommand(`[swap.file: ${options.path}] chmod failed`, result)
}
