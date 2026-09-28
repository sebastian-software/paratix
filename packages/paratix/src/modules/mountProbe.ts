import type { ModuleResult, SshConnection } from "../types.js"
import type { LiveMount } from "./mountTypes.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

export const LIVE_MOUNT_NOT_MOUNTED = "not-mounted"

/**
 * Columns requested from `findmnt` for the live mount at a mountpoint. The
 * parser keys on these literal column names, including `MAJ:MIN` and
 * `VFS-OPTIONS`.
 */
const LIVE_MOUNT_COLUMNS = [
  "ID",
  "PARENT",
  "MAJ:MIN",
  "SOURCE",
  "FSTYPE",
  "OPTIONS",
  "VFS-OPTIONS",
  "FSROOT",
] as const

// Columns whose value must never be empty for a well-formed live mount entry.
const LIVE_MOUNT_NON_EMPTY_COLUMNS = ["ID", "MAJ:MIN", "FSTYPE", "FSROOT"] as const

// One `KEY="value"` pair of `findmnt --pairs` output, followed by the
// separating spaces or the end of the line. findmnt escapes `"`, `\`,
// `` ` ``, `$` and non-printable bytes as `\xNN`, so a raw value never
// contains a double quote and the value ends at the next `"`. The sticky flag
// makes the parser consume a line pair by pair from the start, so anything
// that is not a well-formed pair stops it.
const FINDMNT_PAIR_PATTERN = /(?<key>[A-Z0-9_:\-]+)="(?<value>[^"]*)"(?: +|$)/vy
const FINDMNT_ESCAPE_PATTERN = /\\x(?<hex>[0-9A-Fa-f]{2})/gv
const HEX_RADIX = 16

export type LiveMountProbe =
  | { failure: ModuleResult; kind: "failed" }
  | { kind: "mounted"; live: LiveMount }
  | { kind: typeof LIVE_MOUNT_NOT_MOUNTED }

/**
 * Build the read-only probe for the live mount stack at `path`.
 *
 * `--mountpoint` restricts the output to mounts whose target is exactly
 * `path` (unlike a bare positional argument, which also matches a source
 * device), `--pairs` emits escaped `KEY="value"` pairs so whitespace in a
 * source or option cannot shift columns, and `--nofsroot` keeps SOURCE free of
 * the `[fsroot]` suffix because FSROOT is requested as its own column.
 *
 * @param path - The mountpoint to probe.
 * @returns The `findmnt` command string.
 */
export function buildLiveMountProbeCommand(path: string): string {
  return `findmnt --noheadings --pairs --nofsroot --mountpoint ${shellQuote(path)} --output ${LIVE_MOUNT_COLUMNS.join(",")}`
}

/**
 * Decode findmnt's `\xNN` escapes: every escape becomes one raw byte, and the
 * resulting byte sequence is decoded as UTF-8 so multi-byte characters that
 * findmnt escaped byte-by-byte are restored.
 *
 * @param value - A raw value from `findmnt --pairs` output.
 * @returns The decoded value.
 */
export function decodeFindmntValue(value: string): string {
  if (!value.includes("\\x")) return value
  const encoder = new TextEncoder()
  const bytes: number[] = []
  let lastIndex = 0
  for (const match of value.matchAll(FINDMNT_ESCAPE_PATTERN)) {
    bytes.push(...encoder.encode(value.slice(lastIndex, match.index)))
    bytes.push(Number.parseInt(match.groups?.hex ?? "", HEX_RADIX))
    lastIndex = match.index + match[0].length
  }
  bytes.push(...encoder.encode(value.slice(lastIndex)))
  return new TextDecoder("utf-8").decode(new Uint8Array(bytes))
}

/**
 * Parse one line of `findmnt --pairs` output into a column → decoded value
 * map. Returns `null` when the line contains anything besides well-formed
 * pairs, so malformed output keeps failing closed.
 *
 * @param line - One non-empty output line.
 * @returns The decoded pairs, or `null` for a malformed line.
 */
function parseFindmntPairsLine(line: string): Map<string, string> | null {
  const pairs = new Map<string, string>()
  const trimmed = line.trim()
  FINDMNT_PAIR_PATTERN.lastIndex = 0
  while (FINDMNT_PAIR_PATTERN.lastIndex < trimmed.length) {
    const match = FINDMNT_PAIR_PATTERN.exec(trimmed)
    if (match?.groups == null) return null
    pairs.set(match.groups.key, decodeFindmntValue(match.groups.value))
  }
  return pairs
}

/**
 * Parse every non-empty line of `findmnt --pairs` output and require the
 * given columns on each line.
 *
 * @param stdout - Raw `findmnt --pairs` output.
 * @param requiredColumns - Column names every line must carry.
 * @returns One decoded map per line, or `null` when the output is empty or
 *   any line is malformed or misses a required column.
 */
export function parseFindmntPairs(
  stdout: string,
  requiredColumns: readonly string[]
): Array<Map<string, string>> | null {
  const entries: Array<Map<string, string>> = []
  for (const line of stdout.split("\n")) {
    if (line.trim().length === 0) continue
    const pairs = parseFindmntPairsLine(line)
    if (pairs == null) return null
    if (!requiredColumns.every((column) => pairs.has(column))) return null
    entries.push(pairs)
  }
  return entries.length > 0 ? entries : null
}

/**
 * Pick the top-most mount of a stack at one mountpoint: the entry whose `ID`
 * is not the `PARENT` of another entry in the list. When that is not unique
 * (unexpected output), fall back to the last line, which is where findmnt
 * lists the most recently stacked mount.
 *
 * @param entries - Parsed mounts at the same target, in findmnt order.
 * @returns The top-most entry, or `undefined` for an empty list.
 */
export function selectTopMostMount<T extends { id: string; parent: string }>(
  entries: readonly T[]
): T | undefined {
  const parentIds = new Set(entries.map((entry) => entry.parent))
  const candidates = entries.filter((entry) => !parentIds.has(entry.id))
  if (candidates.length === 1) return candidates[0]
  return entries.at(-1)
}

function toLiveMount(pairs: Map<string, string>): LiveMount | null {
  const column = (name: (typeof LIVE_MOUNT_COLUMNS)[number]): string => pairs.get(name) ?? ""
  if (LIVE_MOUNT_NON_EMPTY_COLUMNS.some((name) => column(name).length === 0)) return null
  return {
    fsroot: column("FSROOT"),
    fstype: column("FSTYPE"),
    id: column("ID"),
    majMin: column("MAJ:MIN"),
    options: column("OPTIONS"),
    parent: column("PARENT"),
    source: column("SOURCE"),
    vfsOptions: column("VFS-OPTIONS"),
  }
}

/**
 * Parse the live mount probe output and select the top-most mount.
 *
 * @param stdout - Output of {@link buildLiveMountProbeCommand}.
 * @returns The top-most live mount, or `null` when the output is malformed.
 */
export function parseLiveMount(stdout: string): LiveMount | null {
  const entries = parseFindmntPairs(stdout, LIVE_MOUNT_COLUMNS)
  if (entries == null) return null
  const mounts: LiveMount[] = []
  for (const pairs of entries) {
    const live = toLiveMount(pairs)
    if (live == null) return null
    mounts.push(live)
  }
  return selectTopMostMount(mounts) ?? null
}

/**
 * Probe the live mount attributes for a mountpoint via
 * {@link buildLiveMountProbeCommand}, distinguishing a genuinely absent mount
 * (findmnt exit code 1) from a failed probe or malformed output.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param moduleName - Module label for failure messages.
 * @param path - The mountpoint to inspect.
 * @returns A structured probe result for mounted, not-mounted, or failed.
 */
export async function probeLiveMount(
  ssh: SshConnection,
  moduleName: string,
  path: string
): Promise<LiveMountProbe> {
  const findmntResult = await ssh.exec(buildLiveMountProbeCommand(path), EXEC_OPTS)
  if (findmntResult.code === 1) return { kind: LIVE_MOUNT_NOT_MOUNTED }
  if (findmntResult.code !== 0) {
    return {
      failure: failedCommand(
        `[${moduleName}: ${path}] findmnt failed while probing live mount state`,
        findmntResult
      ),
      kind: "failed",
    }
  }

  const live = parseLiveMount(findmntResult.stdout)
  if (live == null) {
    return {
      failure: failed(
        `[${moduleName}: ${path}] findmnt returned malformed output while probing live mount state`
      ),
      kind: "failed",
    }
  }
  return { kind: "mounted", live }
}
