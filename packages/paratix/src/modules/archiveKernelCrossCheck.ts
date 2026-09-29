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
 */
import { posix as pathPosix } from "node:path"

import type { SshConnection } from "../types.js"

import { shellQuote } from "../ssh.js"
import { ARCHIVE_CAPTURE_LIMIT_BYTES } from "./archiveMemberValidation.js"
import { type BatchedProbeOutcome, runBatchedProbe } from "./archiveProbe.js"

/**
 * Issue #219: what the kernel reports for one link.
 *
 * - `same`: the link and its expected location both exist and are the same
 *   file (`test -ef`).
 * - `differ`: they are different files, or exactly one of them exists.
 * - `dangling`: neither exists; a dangling link reaches nothing, so there is
 *   nothing outside the destination it could expose.
 */
export type KernelCrossCheckVerdict = "dangling" | "differ" | "same"

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
 * entry `<expected>//<link>` (see {@link kernelCrossCheckEntry}); both halves
 * are normalized absolute paths without `//`, so the first `//` splits them
 * unambiguously. `$\{` keeps the shell parameter expansion literal.
 *
 * `[ / -ef / ]` is a self-test: a `test` without `-ef` support fails it, and
 * the batch exits 65 so the check fails closed instead of reporting every link
 * as `differ` or `dangling` for the wrong reason.
 */
const KERNEL_CROSS_CHECK_SCRIPT = [
  "unset CDPATH; ",
  '[ / -ef / ] || { echo "test -ef is not supported" >&2; exit 65; }; ',
  "for a do ",
  `e=$\{a%%//*}; l=$\{a#*//}; `,
  'if [ -e "$l" ]; then ',
  'if [ -e "$e" ] && [ "$l" -ef "$e" ]; then v=same; else v=differ; fi; ',
  'elif [ -e "$e" ]; then v=differ; else v=dangling; fi; ',
  'printf "%s\\0%s\\0" "$l" "$v"; done; exit 0',
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
 * @returns The remote command. Its output is a flat list of `(link, verdict)`
 *   field pairs, NUL-framed, one per entry, naming the link as it was received.
 */
export function buildKernelCrossCheckScript(): string {
  return `xargs -0 sh -c ${shellQuote(KERNEL_CROSS_CHECK_SCRIPT)} sh`
}

/**
 * Issue #219: whether a path can be transported as one half of a cross-check
 * entry: absolute, normalized, without `//` (which separates the halves) and
 * without NUL (which separates entries).
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
 * Issue #219: encode one entry for {@link buildKernelCrossCheckScript}.
 *
 * @param expected - The absolute path the resolver says the link resolves to.
 * @param link - The absolute path of the link.
 * @returns The entry `<expected>//<link>`, or null when either path cannot be
 *   transported unambiguously (see {@link isTransportablePath}).
 */
export function kernelCrossCheckEntry(expected: string, link: string): null | string {
  if (!isTransportablePath(expected) || !isTransportablePath(link)) return null
  return `${expected}//${link}`
}

/** Issue #219: the parsed cross-check output, or why it cannot be trusted. */
export type KernelCrossCheckResult =
  | { detail: string; kind: "failed" }
  | { kind: "ok"; verdicts: Map<string, KernelCrossCheckVerdict> }

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
 * Issue #219: pair the reported fields into verdicts, refusing anything that
 * was not requested, is reported twice or is not a known verdict.
 *
 * @param expected - The absolute link paths that were sent.
 * @param fields - The decoded fields, an even number of them.
 * @returns The verdict per reported link, or why the output cannot be trusted.
 */
function pairedVerdicts(
  expected: ReadonlySet<string>,
  fields: readonly string[]
): KernelCrossCheckResult {
  const verdicts = new Map<string, KernelCrossCheckVerdict>()
  for (let index = 0; index < fields.length; index += 2) {
    const link = fields[index]
    const verdict = fields[index + 1]
    if (!expected.has(link) || verdicts.has(link)) {
      return crossCheckFailure(`reported unexpected link ${JSON.stringify(link)}`)
    }
    if (!isKernelCrossCheckVerdict(verdict)) {
      return crossCheckFailure(`reported unknown verdict ${JSON.stringify(verdict)}`)
    }
    verdicts.set(link, verdict)
  }
  return { kind: "ok", verdicts }
}

/**
 * Issue #219: parse the cross-check output strictly, failing closed.
 *
 * A failed exec, a truncated capture, an odd field count, an unknown verdict,
 * a link that was not requested, a link reported twice and a requested link
 * without a verdict all make the whole result `failed`.
 *
 * @param requested - The absolute link paths that were sent.
 * @param outcome - The batched probe outcome of the cross-check exec.
 * @returns The verdict per link, or why the output cannot be trusted.
 */
export function kernelCrossCheckVerdicts(
  requested: readonly string[],
  outcome: BatchedProbeOutcome
): KernelCrossCheckResult {
  if (outcome.kind === "failed") return outcome
  const { fields } = outcome
  if (fields.length % 2 !== 0) {
    return crossCheckFailure(
      `returned ${String(fields.length)} fields, expected (link, verdict) pairs`
    )
  }
  const paired = pairedVerdicts(new Set(requested), fields)
  if (paired.kind === "failed") return paired
  const missing = requested.find((link) => !paired.verdicts.has(link))
  if (missing === undefined) return paired
  return crossCheckFailure(`reported no verdict for ${JSON.stringify(missing)}`)
}

/** Issue #219: a link whose location the kernel does not confirm. */
export type KernelMismatch = {
  /** The absolute path the resolver computed for the link. */
  expected: string
  /** Normalized destination-relative path of the link. */
  key: string
}

/**
 * Issue #219: encode one cross-check entry per link judged inside.
 *
 * @param destination - The validated, canonical destination directory.
 * @param inside - Every link judged inside, with its resolved path.
 * @returns The entries and each link's expectation by absolute link path, or
 *   the first link that cannot be transported.
 */
function crossCheckEntries(
  destination: string,
  inside: ReadonlyMap<string, string>
): { entries: string[]; links: Map<string, KernelMismatch> } | { refusedLink: string } {
  const entries: string[] = []
  const links = new Map<string, KernelMismatch>()
  for (const [key, resolved] of inside) {
    const link = `${destination}/${key}`
    const expected = resolved === "" ? destination : `${destination}/${resolved}`
    const entry = kernelCrossCheckEntry(expected, link)
    if (entry === null || links.has(link)) return { refusedLink: link }
    entries.push(entry)
    links.set(link, { expected, key })
  }
  return { entries, links }
}

/**
 * Issue #219: ask the host kernel to confirm the resolver's location of every
 * link judged inside the destination, in one batched exec.
 *
 * `same` and `dangling` confirm the model; `differ` is a mismatch the backstop
 * treats as a violation. Anything that keeps the cross-check from completing —
 * a destination of `/`, a path that cannot be transported, a failed or
 * truncated exec, output that is not valid UTF-8 or not strictly well-formed —
 * is reported as `failed`, which the backstop treats as a failed listing.
 *
 * @param conn - The SSH connection.
 * @param parameters - Cross-check inputs.
 * @param parameters.destination - The validated, canonical destination directory.
 * @param parameters.inside - Every link judged inside, by destination-relative
 *   path, with the destination-relative path it resolves to.
 * @returns The mismatches, or why the cross-check could not be completed.
 */
export async function runKernelCrossCheck(
  conn: SshConnection,
  parameters: { destination: string; inside: ReadonlyMap<string, string> }
): Promise<{ detail: string; kind: "failed" } | { kind: "ok"; mismatches: KernelMismatch[] }> {
  const { destination, inside } = parameters
  if (destination === "/") return crossCheckFailure("the destination is the filesystem root")
  const encoded = crossCheckEntries(destination, inside)
  if ("refusedLink" in encoded) {
    return crossCheckFailure(`cannot transport symlink ${JSON.stringify(encoded.refusedLink)}`)
  }
  // The output grows with the number of links, like the listing, so it gets
  // the archive capture cap; truncation still fails closed.
  const outcome = await runBatchedProbe(conn, {
    entries: encoded.entries,
    maxOutputBytes: ARCHIVE_CAPTURE_LIMIT_BYTES,
    script: buildKernelCrossCheckScript(),
  })
  const parsed = kernelCrossCheckVerdicts([...encoded.links.keys()], outcome)
  if (parsed.kind === "failed") return parsed
  const mismatches = [...encoded.links]
    .filter(([link]) => parsed.verdicts.get(link) === "differ")
    .map(([, mismatch]) => mismatch)
  return { kind: "ok", mismatches }
}
