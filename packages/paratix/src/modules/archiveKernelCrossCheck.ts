/**
 * Kernel cross-check of the post-merge symlink backstop of `archive.extract`.
 *
 * Issue #219: the backstop judges the links below the destination with the
 * lexical resolver in `archiveSymlinkResolver.ts`, which never asks the host
 * to resolve anything. That resolver models how the kernel walks a path; where
 * the model and the host filesystem disagree (for instance on name
 * equivalence), a link the model places inside may resolve elsewhere. This
 * cross-check lets the host kernel confirm the model for every link the
 * resolver judged inside, without ever resolving a path in user space: it only
 * uses `test -e` and `test -ef`, which the kernel bounds with its own `ELOOP`
 * limit, so a self-extending loop cannot hang it (unlike GNU `realpath` or
 * `readlink -f`).
 *
 * Issue #219: a link that reaches nothing is not proof of containment by
 * itself: a write through it creates the missing name wherever the kernel
 * resolves the rest of its target path. For such a link the cross-check
 * therefore compares the nearest existing point of the target path, as the
 * kernel walks it, with the resolver's location of the same point (see
 * {@link KernelCrossCheckVerdict}).
 */
import { posix as pathPosix } from "node:path"

import type { SshConnection } from "../types.js"
import type { SymlinkTrail, SymlinkTrailSource } from "./archiveSymlinkResolver.js"

import { shellQuote } from "../ssh.js"
import { ARCHIVE_CAPTURE_LIMIT_BYTES } from "./archiveMemberValidation.js"
import { type BatchedProbeOutcome, runBatchedProbe } from "./archiveProbe.js"

/**
 * Issue #219: what the kernel reports for one link.
 *
 * - `same`: the link reaches an existing file, and that file is the location
 *   the resolver computed (`test -ef`).
 * - `dangling`: the link reaches nothing, and the nearest existing point of
 *   its target path is where the resolver puts it: walking the target trail
 *   (see {@link SymlinkTrail}) from the full target path towards the link's
 *   directory, the first point that exists on the host or in the model exists
 *   on both sides and is the same file.
 * - `differ`: anything else — the link reaches a different file, or reaches
 *   nothing while the nearest existing point differs, exists on one side only,
 *   or no point of the trail exists at all.
 */
export type KernelCrossCheckVerdict = "dangling" | "differ" | "same"

/**
 * Issue #219: the largest cross-check entry, in bytes, that is sent for one
 * link. One entry is one `xargs` argument; Linux refuses a single argument
 * above `MAX_ARG_STRLEN` (128 KiB), so the bound stays well below it. A
 * relevant link whose entry would be larger fails the cross-check closed. An
 * `xargs` that cannot take an argument of this size fails the exec, which
 * fails the cross-check closed as well.
 */
export const KERNEL_CROSS_CHECK_ENTRY_LIMIT_BYTES = 65_536

/** Issue #219: what separates the paths within one cross-check entry. */
const ENTRY_SEPARATOR = "//"

/** Issue #219: the fields the script prints per link: link, verdict, level. */
const REPORT_FIELD_COUNT = 3

/**
 * Issue #219: narrow a reported verdict field.
 *
 * @param value - The field the script printed.
 * @returns True when it is one of the {@link KernelCrossCheckVerdict} values.
 */
function isKernelCrossCheckVerdict(value: string): value is KernelCrossCheckVerdict {
  return value === "dangling" || value === "differ" || value === "same"
}

/**
 * Per-batch body of {@link buildKernelCrossCheckScript}. Each argument is one
 * entry `<link>//<K_n>//<E_n>//...//<K_0>//<E_0>` (see
 * {@link kernelCrossCheckEntry}); no transported path contains `//`, so every
 * `//` separates two of them. `$\{` keeps the shell parameter expansion
 * literal.
 *
 * A link that exists (`test -e` follows it) is compared with `E_n`. Otherwise
 * the pairs are walked from `n` down to 0 until one side exists; `s` counts
 * the pairs checked, and one past the last pair when none exists. The printed
 * level is 0 for an existing link, otherwise `s`.
 *
 * `[ / -ef / ]` is a self-test: a `test` without `-ef` support fails it, and
 * the batch exits 65 so the check fails closed instead of reporting every link
 * as `differ` or `dangling` for the wrong reason.
 */
const KERNEL_CROSS_CHECK_SCRIPT = [
  "unset CDPATH; ",
  '[ / -ef / ] || { echo "test -ef is not supported" >&2; exit 65; }; ',
  "for a do ",
  `l=$\{a%%//*}; r=$\{a#*//}; s=0; `,
  'if [ -e "$l" ]; then ',
  `r=$\{r#*//}; e=$\{r%%//*}; `,
  'if [ -e "$e" ] && [ "$l" -ef "$e" ]; then v=same; else v=differ; fi; ',
  "else v=differ; ",
  "while :; do ",
  `s=$((s+1)); k=$\{r%%//*}; r=$\{r#*//}; e=$\{r%%//*}; `,
  'if [ -e "$k" ] || [ -e "$e" ]; then ',
  'if [ -e "$k" ] && [ -e "$e" ] && [ "$k" -ef "$e" ]; then v=dangling; fi; ',
  "break; fi; ",
  `case $r in *//*) r=$\{r#*//} ;; *) s=$((s+1)); break ;; esac; `,
  "done; fi; ",
  'printf "%s\\0%s\\0%s\\0" "$l" "$v" "$s"; done; exit 0',
].join("")

/**
 * Issue #219: script that asks the host kernel whether each link resolves to
 * the location the lexical resolver computed for it.
 *
 * It is meant for {@link runBatchedProbe} with one entry per link (see
 * {@link kernelCrossCheckEntry}), so it costs exactly one exec regardless of
 * the number of links. Per entry it reports the verdict described at
 * {@link KernelCrossCheckVerdict}. `test -e` follows the link like any path
 * lookup, and `test -ef` compares device and inode of the two resolved files;
 * neither resolves a path in user space.
 *
 * @returns The remote command. Its output is a flat list of
 *   `(link, verdict, level)` field triples, NUL-framed, one per entry, naming
 *   the link as it was received; see {@link KernelCrossCheckReport} for the
 *   level.
 */
export function buildKernelCrossCheckScript(): string {
  return `xargs -0 sh -c ${shellQuote(KERNEL_CROSS_CHECK_SCRIPT)} sh`
}

/**
 * Issue #219: whether a normalized path can be transported in a cross-check
 * entry: absolute, normalized, without `//` (which separates the paths) and
 * without NUL (which separates entries). The link and every expected location
 * `E_j` must pass it.
 *
 * @param path - The path to check.
 * @returns True when the path may be sent.
 */
function isTransportablePath(path: string): boolean {
  if (!path.startsWith("/") || path.includes("\0") || path.includes("//")) return false
  if (path.length > 1 && path.endsWith("/")) return false
  return pathPosix.normalize(path) === path
}

/**
 * Issue #219: whether a host trail path `K_j` can be transported in a
 * cross-check entry. Unlike an expected location it keeps its `..` segments,
 * because the kernel has to walk them, but it is still absolute, not the root
 * itself, and free of NUL, empty segments (so no `//` and no trailing `/`)
 * and `.` segments.
 *
 * @param path - The path to check.
 * @returns True when the path may be sent.
 */
export function isTransportableTrailPath(path: string): boolean {
  if (!path.startsWith("/") || path.includes("\0")) return false
  return path
    .slice(1)
    .split("/")
    .every((segment) => segment !== "" && segment !== ".")
}

/**
 * Issue #219: one point of a link's target trail as absolute paths: the path
 * the kernel walks (`host`, `K_j`) and the resolver's location of the same
 * point (`expected`, `E_j`).
 */
export type KernelCrossCheckPoint = { expected: string; host: string }

/**
 * Issue #219: one encoded cross-check entry, or why a link cannot be sent:
 * `oversized` above {@link KERNEL_CROSS_CHECK_ENTRY_LIMIT_BYTES}, or
 * `invalid-path` when a path cannot be split unambiguously.
 */
export type KernelCrossCheckEntry =
  { entry: string; kind: "entry" } | { kind: "invalid-path" } | { kind: "oversized" }

/** Issue #219: the entry result for a path that cannot be transported. */
const INVALID_PATH = { kind: "invalid-path" } as const

/**
 * Issue #219: encode one entry for {@link buildKernelCrossCheckScript}.
 *
 * @param link - The absolute path of the link.
 * @param points - The trail points `j = 0..n` (see {@link SymlinkTrail}), in
 *   that order; the last one's `expected` is the link's resolved location.
 * @returns The entry `<link>//<K_n>//<E_n>//...//<K_0>//<E_0>`; `oversized`
 *   when it would exceed {@link KERNEL_CROSS_CHECK_ENTRY_LIMIT_BYTES}, and
 *   `invalid-path` when a path cannot be transported unambiguously (see
 *   {@link isTransportableTrailPath}) or no point is given.
 */
export function kernelCrossCheckEntry(
  link: string,
  points: readonly KernelCrossCheckPoint[]
): KernelCrossCheckEntry {
  if (points.length === 0 || !isTransportablePath(link)) return INVALID_PATH
  const parts = [link]
  for (const { expected, host } of points.toReversed()) {
    if (!isTransportableTrailPath(host) || !isTransportablePath(expected)) return INVALID_PATH
    parts.push(host, expected)
  }
  const entry = parts.join(ENTRY_SEPARATOR)
  if (Buffer.byteLength(entry) > KERNEL_CROSS_CHECK_ENTRY_LIMIT_BYTES) return { kind: "oversized" }
  return { entry, kind: "entry" }
}

/**
 * Issue #219: the absolute path of a destination-relative location.
 *
 * @param destination - The validated, canonical destination directory.
 * @param location - A normalized destination-relative path, `""` for the root.
 * @returns The absolute path.
 */
function absoluteLocation(destination: string, location: string): string {
  return location === "" ? destination : `${destination}/${location}`
}

/**
 * Issue #219: the absolute trail points of one link (see
 * {@link KernelCrossCheckPoint}), built one by one so an oversized trail is
 * refused before all of its paths exist.
 *
 * @param destination - The validated, canonical destination directory.
 * @param trail - The link's trail from the resolver.
 * @returns The points `j = 0..n`, or `"oversized"` when their summed length
 *   alone exceeds {@link KERNEL_CROSS_CHECK_ENTRY_LIMIT_BYTES}.
 */
function trailPoints(
  destination: string,
  trail: SymlinkTrail
): "oversized" | KernelCrossCheckPoint[] {
  const points: KernelCrossCheckPoint[] = []
  let host = absoluteLocation(destination, trail.base)
  let length = 0
  for (const [index, location] of trail.locations.entries()) {
    if (index > 0) host = `${host}/${trail.segments[index - 1]}`
    const expected = absoluteLocation(destination, location)
    // A UTF-16 code unit never encodes to fewer bytes, so a longer string is
    // certainly an oversized entry.
    length += host.length + expected.length + ENTRY_SEPARATOR.length + ENTRY_SEPARATOR.length
    if (length > KERNEL_CROSS_CHECK_ENTRY_LIMIT_BYTES) return "oversized"
    points.push({ expected, host })
  }
  return points
}

/**
 * Issue #219: one link's report: the verdict and the level at which it was
 * decided. Level 0 means the link reaches an existing file, compared with its
 * resolved location. A level `m` from 1 to `n + 1` means the link reaches
 * nothing and the trail point `j = n + 1 - m` was the first where either side
 * exists; `n + 2` means no trail point exists on either side.
 */
export type KernelCrossCheckReport = { level: number; verdict: KernelCrossCheckVerdict }

/** Issue #219: the parsed cross-check output, or why it cannot be trusted. */
export type KernelCrossCheckResult =
  { detail: string; kind: "failed" } | { kind: "ok"; reports: Map<string, KernelCrossCheckReport> }

/**
 * Issue #219: a cross-check result that cannot be trusted.
 *
 * @param detail - Why.
 * @returns The failed result.
 */
function crossCheckFailure(detail: string): { detail: string; kind: "failed" } {
  return { detail, kind: "failed" }
}

/**
 * Issue #219: parse a reported level strictly and check it against the
 * verdict and the number of trail segments.
 *
 * @param field - The level field the script printed.
 * @param verdict - The verdict reported with it.
 * @param segments - The number of trail segments `n` of the link.
 * @returns The level, or null when it is malformed, out of range or
 *   inconsistent with the verdict.
 */
function reportedLevel(
  field: string,
  verdict: KernelCrossCheckVerdict,
  segments: number
): null | number {
  if (!/^(?:0|[1-9]\d{0,9})$/v.test(field)) return null
  const level = Number(field)
  switch (verdict) {
    case "dangling": {
      return level >= 1 && level <= segments + 1 ? level : null
    }
    case "differ": {
      return level <= segments + 2 ? level : null
    }
    case "same": {
      return level === 0 ? level : null
    }
  }
}

/**
 * Issue #219: group the reported fields into reports, refusing anything that
 * was not requested, is reported twice, is not a known verdict or carries an
 * invalid level.
 *
 * @param requested - The absolute link paths that were sent, each with its
 *   number of trail segments.
 * @param fields - The decoded fields, a multiple of three.
 * @returns The report per reported link, or why the output cannot be trusted.
 */
function groupedReports(
  requested: ReadonlyMap<string, number>,
  fields: readonly string[]
): KernelCrossCheckResult {
  const reports = new Map<string, KernelCrossCheckReport>()
  for (let index = 0; index < fields.length; index += REPORT_FIELD_COUNT) {
    const link = fields[index]
    const verdict = fields[index + 1]
    const segments = requested.get(link)
    if (segments === undefined || reports.has(link)) {
      return crossCheckFailure(`reported unexpected link ${JSON.stringify(link)}`)
    }
    if (!isKernelCrossCheckVerdict(verdict)) {
      return crossCheckFailure(`reported unknown verdict ${JSON.stringify(verdict)}`)
    }
    const level = reportedLevel(fields[index + 2], verdict, segments)
    if (level === null) {
      return crossCheckFailure(
        `reported invalid level ${JSON.stringify(fields[index + 2])} for ${JSON.stringify(link)}`
      )
    }
    reports.set(link, { level, verdict })
  }
  return { kind: "ok", reports }
}

/**
 * Issue #219: parse the cross-check output strictly, failing closed.
 *
 * A failed exec, a truncated capture, a field count that is not a multiple of
 * three, an unknown verdict, a malformed or inconsistent level, a link that
 * was not requested, a link reported twice and a requested link without a
 * report all make the whole result `failed`.
 *
 * @param requested - The absolute link paths that were sent, each with its
 *   number of trail segments `n`.
 * @param outcome - The batched probe outcome of the cross-check exec.
 * @returns The report per link, or why the output cannot be trusted.
 */
export function kernelCrossCheckVerdicts(
  requested: ReadonlyMap<string, number>,
  outcome: BatchedProbeOutcome
): KernelCrossCheckResult {
  if (outcome.kind === "failed") return outcome
  const { fields } = outcome
  if (fields.length % REPORT_FIELD_COUNT !== 0) {
    return crossCheckFailure(
      `returned ${String(fields.length)} fields, expected (link, verdict, level) triples`
    )
  }
  const grouped = groupedReports(requested, fields)
  if (grouped.kind === "failed") return grouped
  const missing = [...requested.keys()].find((link) => !grouped.reports.has(link))
  if (missing === undefined) return grouped
  return crossCheckFailure(`reported no verdict for ${JSON.stringify(missing)}`)
}

/**
 * Issue #219: where the kernel does not confirm the resolver.
 *
 * - `link`: the link reaches an existing file other than its resolved
 *   location.
 * - `point`: the link reaches nothing, and at the nearest trail point where
 *   either side exists, the host path (`host`) and the resolver's location
 *   (`location`) are not the same existing file.
 * - `none`: the link reaches nothing, and no point of its trail exists on
 *   either side.
 */
export type KernelMismatchPoint =
  { host: string; kind: "point"; location: string } | { kind: "link" } | { kind: "none" }

/** Issue #219: a link whose location the kernel does not confirm. */
export type KernelMismatch = {
  /** Issue #219: where the kernel and the resolver disagree. */
  at: KernelMismatchPoint
  /** The absolute path the resolver computed for the link. */
  expected: string
  /** Normalized destination-relative path of the link. */
  key: string
}

/** Issue #219: what the cross-check remembers of one sent link. */
type SentLink = { expected: string; key: string; segments: number }

/**
 * Issue #219: why a link cannot be sent, as a cross-check failure detail.
 *
 * @param link - The absolute link path.
 * @param reason - Whether its entry is too large or cannot be encoded.
 * @returns The refusal.
 */
function refusedLink(
  link: string,
  reason: "invalid-path" | "oversized" | "untraceable"
): { refused: string } {
  const quoted = JSON.stringify(link)
  switch (reason) {
    case "invalid-path": {
      return { refused: `cannot transport symlink ${quoted}` }
    }
    case "oversized": {
      return {
        refused: `the cross-check entry of symlink ${quoted} would exceed ${String(KERNEL_CROSS_CHECK_ENTRY_LIMIT_BYTES)} bytes`,
      }
    }
    case "untraceable": {
      return { refused: `cannot trace symlink ${quoted}` }
    }
  }
}

/**
 * Issue #219: encode the cross-check entry of one link judged inside,
 * computing its trail only for this entry.
 *
 * @param destination - The validated, canonical destination directory.
 * @param key - The link's destination-relative path.
 * @param trail - The trail source of the resolver that judged it.
 * @returns The entry with what was sent, or why the link cannot be sent.
 */
function encodedLink(
  destination: string,
  key: string,
  trail: SymlinkTrailSource
): { entry: string; sent: SentLink } | { refused: string } {
  const link = absoluteLocation(destination, key)
  const traced = trail(key, KERNEL_CROSS_CHECK_ENTRY_LIMIT_BYTES)
  if (traced === null) return refusedLink(link, "untraceable")
  if (traced === "oversized") return refusedLink(link, "oversized")
  const points = trailPoints(destination, traced)
  if (points === "oversized") return refusedLink(link, "oversized")
  const encoded = kernelCrossCheckEntry(link, points)
  if (encoded.kind !== "entry") return refusedLink(link, encoded.kind)
  const expected = points.at(-1)?.expected ?? destination
  return { entry: encoded.entry, sent: { expected, key, segments: traced.segments.length } }
}

/**
 * Issue #219: encode one cross-check entry per link judged inside, computing
 * each link's trail only while its entry is built.
 *
 * @param destination - The validated, canonical destination directory.
 * @param keys - Every link judged inside, by destination-relative path.
 * @param trail - The trail source of the resolver that judged them.
 * @returns The entries and what was sent per absolute link path, or why a
 *   link cannot be sent.
 */
function crossCheckEntries(
  destination: string,
  keys: Iterable<string>,
  trail: SymlinkTrailSource
): { entries: string[]; links: Map<string, SentLink> } | { refused: string } {
  const entries: string[] = []
  const links = new Map<string, SentLink>()
  for (const key of keys) {
    const link = absoluteLocation(destination, key)
    if (links.has(link)) return refusedLink(link, INVALID_PATH.kind)
    const encoded = encodedLink(destination, key, trail)
    if ("refused" in encoded) return encoded
    entries.push(encoded.entry)
    links.set(link, encoded.sent)
  }
  return { entries, links }
}

/**
 * Issue #219: describe where the kernel disagrees for one `differ` report.
 *
 * @param parameters - The report to describe.
 * @param parameters.destination - The validated, canonical destination directory.
 * @param parameters.level - The level reported with the `differ` verdict.
 * @param parameters.sent - What was sent for the link.
 * @param parameters.trail - The trail source, to name the trail point again.
 * @returns Where the kernel and the resolver disagree.
 */
function mismatchPoint(parameters: {
  destination: string
  level: number
  sent: SentLink
  trail: SymlinkTrailSource
}): KernelMismatchPoint {
  const { destination, level, sent, trail } = parameters
  if (level === 0) return { kind: "link" }
  const index = sent.segments + 1 - level
  if (index < 0) return { kind: "none" }
  const traced = trail(sent.key, KERNEL_CROSS_CHECK_ENTRY_LIMIT_BYTES)
  const points = traced === null || traced === "oversized" ? [] : trailPoints(destination, traced)
  const point = points === "oversized" ? undefined : points[index]
  // Unreachable: the same trail was sent a moment ago.
  if (point === undefined) return { kind: "link" }
  return { host: point.host, kind: "point", location: point.expected }
}

/**
 * Issue #219: ask the host kernel to confirm the resolver's location of every
 * link judged inside the destination, in one batched exec.
 *
 * `same` and `dangling` confirm the model; `differ` is a mismatch the backstop
 * treats as a violation. Anything that keeps the cross-check from completing —
 * a destination of `/`, a path that cannot be transported, an entry above
 * {@link KERNEL_CROSS_CHECK_ENTRY_LIMIT_BYTES}, a failed or truncated exec,
 * output that is not valid UTF-8 or not strictly well-formed — is reported as
 * `failed`, which the backstop treats as a failed listing. Only relevant links
 * judged inside reach the cross-check, so only such a link can make its entry
 * too large.
 *
 * @param conn - The SSH connection.
 * @param parameters - Cross-check inputs.
 * @param parameters.destination - The validated, canonical destination directory.
 * @param parameters.links - Every link judged inside, by destination-relative
 *   path.
 * @param parameters.trail - The trail source of the resolver that judged them
 *   (see {@link SymlinkTrail}); a trail is computed only while its link's
 *   entry is built, and again for a mismatch.
 * @returns The mismatches, or why the cross-check could not be completed.
 */
export async function runKernelCrossCheck(
  conn: SshConnection,
  parameters: { destination: string; links: Iterable<string>; trail: SymlinkTrailSource }
): Promise<{ detail: string; kind: "failed" } | { kind: "ok"; mismatches: KernelMismatch[] }> {
  const { destination, trail } = parameters
  if (destination === "/") return crossCheckFailure("the destination is the filesystem root")
  const encoded = crossCheckEntries(destination, parameters.links, trail)
  if ("refused" in encoded) return crossCheckFailure(encoded.refused)
  // The output grows with the number of links, like the listing, so it gets
  // the archive capture cap; truncation still fails closed.
  const outcome = await runBatchedProbe(conn, {
    entries: encoded.entries,
    maxOutputBytes: ARCHIVE_CAPTURE_LIMIT_BYTES,
    script: buildKernelCrossCheckScript(),
  })
  const requested = new Map([...encoded.links].map(([link, sent]) => [link, sent.segments]))
  const parsed = kernelCrossCheckVerdicts(requested, outcome)
  if (parsed.kind === "failed") return parsed
  const mismatches: KernelMismatch[] = []
  for (const [link, sent] of encoded.links) {
    const report = parsed.reports.get(link)
    if (report?.verdict !== "differ") continue
    const at = mismatchPoint({ destination, level: report.level, sent, trail })
    mismatches.push({ at, expected: sent.expected, key: sent.key })
  }
  return { kind: "ok", mismatches }
}
