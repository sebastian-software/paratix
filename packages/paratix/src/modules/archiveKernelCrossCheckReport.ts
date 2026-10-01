/**
 * Issue #219: strict parsing of the kernel cross-check output of
 * `archive.extract`, split out of `archiveKernelCrossCheck.ts`. Anything the
 * script did not report exactly as requested fails the cross-check closed.
 */
import type { BatchedProbeOutcome } from "./archiveProbe.js"

import { ARCHIVE_CAPTURE_LIMIT_BYTES } from "./archiveMemberValidation.js"

/**
 * Issue #219: what the kernel reports for one link.
 *
 * - `same`: the link reaches an existing file, and that file is the location
 *   the resolver computed (`test -ef`).
 * - `dangling`: the link reaches nothing, and the nearest existing point of
 *   its target path is where the resolver puts it: walking the target trail
 *   (see `SymlinkTrail`) from the full target path towards the link's
 *   directory, the first point that exists on the host or in the model exists
 *   on both sides and is the same file.
 * - `differ`: anything else — the link reaches a different file, or reaches
 *   nothing while the nearest existing point differs, exists on one side only,
 *   or no point of the trail exists at all.
 */
export type KernelCrossCheckVerdict = "dangling" | "differ" | "same"

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
export function crossCheckFailure(detail: string): { detail: string; kind: "failed" } {
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
 * Issue #219: why the cross-check output was cut off at the archive capture
 * cap. The output is one short report per sent link, so it only grows that
 * large with very many checked symlinks or very long symlink paths.
 */
const CROSS_CHECK_OUTPUT_OVERFLOW = `too many symlinks to cross-check, or symlink paths too long: the cross-check output exceeded its captured-output cap of ${String(ARCHIVE_CAPTURE_LIMIT_BYTES)} bytes`

/**
 * Issue #219: parse the cross-check output strictly, failing closed.
 *
 * A failed exec, a truncated capture, a field count that is not a multiple of
 * three, an unknown verdict, a malformed or inconsistent level, a link that
 * was not requested, a link reported twice and a requested link without a
 * report all make the whole result `failed`. A truncated capture names its
 * cause, see {@link CROSS_CHECK_OUTPUT_OVERFLOW}.
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
  if (outcome.kind === "failed") {
    return crossCheckFailure(
      outcome.truncated === true ? CROSS_CHECK_OUTPUT_OVERFLOW : outcome.detail
    )
  }
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
