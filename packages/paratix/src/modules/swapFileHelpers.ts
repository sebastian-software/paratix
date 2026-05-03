import { dirname } from "node:path"

import { failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { guardedWriteFile, type ModuleResult, type SshConnection } from "../types.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const FSTAB_PATH = "/etc/fstab"
const FSTAB_MODE = "0644"
const KIBI = 1024
const MEBI = KIBI * KIBI
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

function normalizeSizeToBytes(size: number | string): number {
  if (typeof size === "number") {
    if (!Number.isInteger(size) || size <= 0) {
      throw new Error("swap.file: numeric size must be a positive integer byte count")
    }
    return size
  }

  const trimmed = size.trim()
  const match = /^(?<value>\d+)(?<unit>[KMGTP]?)$/iv.exec(trimmed)
  if (match?.groups == null) {
    throw new Error(`swap.file: unsupported size format "${size}"`)
  }

  const value = Number.parseInt(match.groups.value, 10)
  const unit = match.groups.unit.toUpperCase()
  if (!isSizeUnit(unit)) {
    throw new Error(`swap.file: unsupported size unit "${unit}"`)
  }
  return value * KIBI ** SIZE_POWERS[unit]
}

function normalizeSizeForCommand(size: number | string): string {
  return typeof size === "number" ? String(size) : size.trim()
}

function buildSwapFstabLine(path: string, priority?: number): string {
  const options = priority == null ? "sw" : `sw,pri=${String(priority)}`
  return `${path} none swap ${options} 0 0`
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

export async function ensureSwapFilePresent(parameters: {
  mode: string
  path: string
  size: string
  sizeBytes: number
  ssh: SshConnection
}): Promise<ModuleResult | true> {
  const createDirectoryResult = await parameters.ssh.exec(
    `mkdir -p ${shellQuote(dirname(parameters.path))}`,
    EXEC_OPTS
  )
  if (createDirectoryResult.code !== 0) {
    return failedCommand(`[swap.file: ${parameters.path}] mkdir failed`, createDirectoryResult)
  }

  // Use 1 MiB block size in the dd fallback so we never allocate the full swap
  // size as a single buffer in RAM (which can OOM tiny VMs that need swap)
  // and so BusyBox dd, which does not support multi-gigabyte block sizes,
  // still works.
  const ddBlockCount = Math.ceil(parameters.sizeBytes / MEBI)
  const createFileResult = await parameters.ssh.exec(
    `fallocate -l ${shellQuote(parameters.size)} ${shellQuote(parameters.path)} || dd if=/dev/zero of=${shellQuote(parameters.path)} bs=1M count=${String(ddBlockCount)} status=none`,
    EXEC_OPTS
  )
  if (createFileResult.code !== 0) {
    return failedCommand(
      `[swap.file: ${parameters.path}] swap file creation failed`,
      createFileResult
    )
  }

  const chmodResult = await parameters.ssh.exec(
    `chmod ${shellQuote(parameters.mode)} ${shellQuote(parameters.path)}`,
    EXEC_OPTS
  )
  if (chmodResult.code !== 0) {
    return failedCommand(`[swap.file: ${parameters.path}] chmod failed`, chmodResult)
  }

  const makeSwapResult = await parameters.ssh.exec(
    `mkswap ${shellQuote(parameters.path)}`,
    EXEC_OPTS
  )
  return makeSwapResult.code === 0
    ? true
    : failedCommand(`[swap.file: ${parameters.path}] mkswap failed`, makeSwapResult)
}

export function normalizeSwapFileOptions(options: {
  mode?: string
  path: string
  priority?: number
  size: number | string
  state?: "absent" | "present"
}): NormalizedSwapFileOptions {
  const state = options.state ?? "present"
  return {
    expectedFstabLine:
      state === "present" ? buildSwapFstabLine(options.path, options.priority) : null,
    mode: options.mode ?? "0600",
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
