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
 * `KernelCrossCheckVerdict`).
 */
import { posix as pathPosix } from "node:path"

import type { SshConnection } from "../types.js"
import type { KernelCrossCheckReport } from "./archiveKernelCrossCheckReport.js"
import type { SymlinkTrail, SymlinkTrailSource } from "./archiveSymlinkResolver.js"

import { shellQuote } from "../ssh.js"
import { crossCheckFailure, kernelCrossCheckVerdicts } from "./archiveKernelCrossCheckReport.js"
import { ARCHIVE_CAPTURE_LIMIT_BYTES } from "./archiveMemberValidation.js"
import { runBatchedProbe } from "./archiveProbe.js"

export {
  type KernelCrossCheckReport,
  type KernelCrossCheckResult,
  type KernelCrossCheckVerdict,
  kernelCrossCheckVerdicts,
} from "./archiveKernelCrossCheckReport.js"

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
 * `KernelCrossCheckVerdict`. `test -e` follows the link like any path
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

/**
 * Issue #219: a link whose location the kernel does not confirm. With `via`,
 * the link itself was confirmed or reaches nothing, but the kernel does not
 * confirm the followed link `via` (see `followed` at
 * {@link runKernelCrossCheck}); `at` and `expected` then describe `via`.
 */
export type KernelMismatch = {
  /** Issue #219: where the kernel and the resolver disagree. */
  at: KernelMismatchPoint
  /** The absolute path the resolver computed for the link, or for `via`. */
  expected: string
  /** Normalized destination-relative path of the link. */
  key: string
  /** Normalized destination-relative path of the followed link that differs. */
  via?: string
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
 * Issue #219: the followed links of every judged link that are not judged
 * themselves, see `followed` at {@link runKernelCrossCheck}.
 *
 * @param judged - Every link judged inside, in order.
 * @param followed - The followed links of one judged link.
 * @returns The followed links per judged link that follows any.
 */
function followedLinksOf(
  judged: readonly string[],
  followed: ((key: string) => readonly string[]) | undefined
): Map<string, string[]> {
  const byLink = new Map<string, string[]>()
  if (followed === undefined) return byLink
  const judgedLinks = new Set(judged)
  for (const key of judged) {
    const links = followed(key).filter((link) => !judgedLinks.has(link))
    if (links.length > 0) byLink.set(key, links)
  }
  return byLink
}

/** Issue #219: where the kernel disagrees for one sent link, before it is attributed. */
type LinkMismatch = Omit<KernelMismatch, "key" | "via">

/**
 * Issue #219: every sent link the kernel reported as `differ`, with where it
 * differs.
 *
 * @param parameters - The parsed cross-check.
 * @param parameters.destination - The validated, canonical destination directory.
 * @param parameters.reports - The report per absolute link path.
 * @param parameters.sent - What was sent per absolute link path.
 * @param parameters.trail - The trail source, to name a trail point again.
 * @returns The mismatch per destination-relative link path.
 */
function differingLinks(parameters: {
  destination: string
  reports: ReadonlyMap<string, KernelCrossCheckReport>
  sent: ReadonlyMap<string, SentLink>
  trail: SymlinkTrailSource
}): Map<string, LinkMismatch> {
  const { destination, reports, trail } = parameters
  const differing = new Map<string, LinkMismatch>()
  for (const [link, sent] of parameters.sent) {
    const report = reports.get(link)
    if (report?.verdict !== "differ") continue
    const at = mismatchPoint({ destination, level: report.level, sent, trail })
    differing.set(sent.key, { at, expected: sent.expected })
  }
  return differing
}

/**
 * Issue #219: attribute the mismatches to the judged links: each judged
 * link's own, then those of the links it follows, under the judged link with
 * the followed one as `via`.
 *
 * @param judged - Every link judged inside, in order.
 * @param followedBy - The unjudged followed links per judged link.
 * @param differing - The mismatch per sent link.
 * @returns The mismatches in the order of `judged`.
 */
function judgedMismatches(
  judged: readonly string[],
  followedBy: ReadonlyMap<string, readonly string[]>,
  differing: ReadonlyMap<string, LinkMismatch>
): KernelMismatch[] {
  const mismatches: KernelMismatch[] = []
  for (const key of judged) {
    const own = differing.get(key)
    if (own !== undefined) mismatches.push({ ...own, key })
    for (const via of followedBy.get(key) ?? []) {
      const followed = differing.get(via)
      if (followed !== undefined) mismatches.push({ ...followed, key, via })
    }
  }
  return mismatches
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
 * `failed`, which the backstop treats as a failed listing. An exec rejection
 * that {@link runBatchedProbe} does not map to `failed`, such as a dropped
 * connection, propagates instead. Only relevant links judged inside and the
 * links they follow reach the cross-check, so only such a link can make its
 * entry too large. Output beyond the archive capture cap names its cause.
 *
 * Issue #219: a judged link that follows another link whose target dangles is
 * reported `dangling` as soon as its own trail agrees with the model up to
 * that link; where a write through it would land depends on how the kernel
 * resolves the followed link's target. Every followed link that is not judged
 * itself is therefore sent once with its own trail, however many judged links
 * follow it, and a `differ` for it becomes a mismatch of each judged link that
 * follows it, with the followed link as `via`. The followed link never becomes
 * a mismatch of its own, so the caller does not judge or record it.
 *
 * @param conn - The SSH connection.
 * @param parameters - Cross-check inputs.
 * @param parameters.destination - The validated, canonical destination directory.
 * @param parameters.followed - Issue #219: the links the resolution of a
 *   judged link follows; a followed link that is judged itself is checked
 *   only as its own entry. None when omitted.
 * @param parameters.links - Every link judged inside, by destination-relative
 *   path.
 * @param parameters.trail - The trail source of the resolver that judged them
 *   (see {@link SymlinkTrail}); a trail is computed only while its link's
 *   entry is built, and again for a mismatch.
 * @returns The mismatches, each judged link's own before those of the links
 *   it follows, in the order of `links`, or why the cross-check could not be
 *   completed.
 * @throws {Error} The exec rejections `runBatchedProbe` propagates.
 */
export async function runKernelCrossCheck(
  conn: SshConnection,
  parameters: {
    destination: string
    followed?: (key: string) => readonly string[]
    links: Iterable<string>
    trail: SymlinkTrailSource
  }
): Promise<{ detail: string; kind: "failed" } | { kind: "ok"; mismatches: KernelMismatch[] }> {
  const { destination, trail } = parameters
  if (destination === "/") return crossCheckFailure("the destination is the filesystem root")
  const judged = [...parameters.links]
  const followedBy = followedLinksOf(judged, parameters.followed)
  const followedLinks = new Set([...followedBy.values()].flat())
  const encoded = crossCheckEntries(destination, [...judged, ...followedLinks], trail)
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
  const differing = differingLinks({
    destination,
    reports: parsed.reports,
    sent: encoded.links,
    trail,
  })
  return { kind: "ok", mismatches: judgedMismatches(judged, followedBy, differing) }
}
