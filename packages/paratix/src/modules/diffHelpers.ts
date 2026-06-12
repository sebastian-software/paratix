/**
 * Minimal line-based unified-diff helpers used by modules that opt into
 * `--diff` dry-run output via the `_dryRunDiffProducer` marker.
 *
 * The helper intentionally avoids an external diff library: only a couple of
 * modules currently need it, the algorithm is small, and a hand-rolled
 * implementation keeps the dependency surface of the published package narrow.
 *
 * Output format: a stripped-down unified diff. The header lines
 * (`--- current`, `+++ desired`) describe the two sides; hunk headers (`@@`)
 * are emitted per contiguous change region with a configurable number of
 * surrounding context lines.
 *
 * Security: the helper never sees registered secrets directly — masking and
 * terminal sanitizing happen in the output layer when each diff line is
 * printed, so secret-laden file contents never reach the terminal verbatim.
 */

const DEFAULT_CONTEXT_LINES = 3

/**
 * Soft cap on the size of the LCS dynamic-programming table allocated by
 * {@link buildUnifiedDiff}. The table is `(currentLines.length + 1) *
 * (desiredLines.length + 1)` entries; one million cells corresponds to roughly
 * 8 MB of heap (V8 packed-smi arrays) for the table itself, which keeps the
 * diff helper inside the budget of the runner even on memory-constrained
 * agents. Inputs above the cap fall back to a degenerate "all-delete +
 * all-insert" diff that is still format-conformant — the hunk just gets
 * larger, but the helper never allocates an O(n*m) table that could exhaust
 * memory.
 */
const MAX_DIFF_CELLS = 1_000_000

export type UnifiedDiffOptions = {
  /** Number of unchanged lines printed before and after each change hunk. Defaults to 3. */
  contextLines?: number
  /** Label printed on the `--- <label>` header. Defaults to `"current"`. */
  currentLabel?: string
  /** Label printed on the `+++ <label>` header. Defaults to `"desired"`. */
  desiredLabel?: string
}

type DiffOperation = "context" | "delete" | "insert"

type DiffLine = {
  operation: DiffOperation
  text: string
}

function normalizeLineEndings(content: string): string {
  return content.replaceAll("\r\n", "\n")
}

function splitLines(content: string): string[] {
  if (content === "") return []
  // Preserve the empty trailing line that a final "\n" implies so that diffs
  // around the end of the file render the trailing newline as a tracked
  // (un)changed line rather than silently dropping it.
  return content.split("\n")
}

function buildLcsTable(currentLines: string[], desiredLines: string[]): number[][] {
  const rows = currentLines.length + 1
  const cols = desiredLines.length + 1
  const table: number[][] = []
  for (let rowIndex = 0; rowIndex < rows; rowIndex++) {
    table.push(Array.from<number>({ length: cols }).fill(0))
  }
  for (let rowIndex = 1; rowIndex < rows; rowIndex++) {
    for (let colIndex = 1; colIndex < cols; colIndex++) {
      if (currentLines[rowIndex - 1] === desiredLines[colIndex - 1]) {
        table[rowIndex][colIndex] = table[rowIndex - 1][colIndex - 1] + 1
      } else {
        table[rowIndex][colIndex] = Math.max(
          table[rowIndex - 1][colIndex],
          table[rowIndex][colIndex - 1]
        )
      }
    }
  }
  return table
}

type BacktrackStep = {
  diffLine: DiffLine
  nextCol: number
  nextRow: number
}

function nextBacktrackStep(input: {
  colIndex: number
  currentLines: string[]
  desiredLines: string[]
  rowIndex: number
  table: number[][]
}): BacktrackStep {
  const { colIndex, currentLines, desiredLines, rowIndex, table } = input
  if (rowIndex > 0 && colIndex > 0 && currentLines[rowIndex - 1] === desiredLines[colIndex - 1]) {
    return {
      diffLine: { operation: "context", text: currentLines[rowIndex - 1] },
      nextCol: colIndex - 1,
      nextRow: rowIndex - 1,
    }
  }
  if (
    colIndex > 0 &&
    (rowIndex === 0 || table[rowIndex][colIndex - 1] >= table[rowIndex - 1][colIndex])
  ) {
    return {
      diffLine: { operation: "insert", text: desiredLines[colIndex - 1] },
      nextCol: colIndex - 1,
      nextRow: rowIndex,
    }
  }
  return {
    diffLine: { operation: "delete", text: currentLines[rowIndex - 1] },
    nextCol: colIndex,
    nextRow: rowIndex - 1,
  }
}

function backtrackLcs(input: {
  currentLines: string[]
  desiredLines: string[]
  table: number[][]
}): DiffLine[] {
  const diff: DiffLine[] = []
  let rowIndex = input.currentLines.length
  let colIndex = input.desiredLines.length
  while (rowIndex > 0 || colIndex > 0) {
    const step = nextBacktrackStep({
      colIndex,
      currentLines: input.currentLines,
      desiredLines: input.desiredLines,
      rowIndex,
      table: input.table,
    })
    diff.push(step.diffLine)
    rowIndex = step.nextRow
    colIndex = step.nextCol
  }
  diff.reverse()
  return diff
}

function buildFallbackLineDiff(currentLines: string[], desiredLines: string[]): DiffLine[] {
  // R-0001017: when the LCS table would exceed `MAX_DIFF_CELLS`, fall back to
  // a degenerate diff that deletes every current line and inserts every
  // desired line. The output remains a structurally valid unified diff (just
  // a single oversized hunk), and the helper never allocates the O(n*m)
  // table that could otherwise exhaust memory on huge inputs.
  const fallback: DiffLine[] = []
  for (const text of currentLines) fallback.push({ operation: "delete", text })
  for (const text of desiredLines) fallback.push({ operation: "insert", text })
  return fallback
}

function computeLineDiff(currentLines: string[], desiredLines: string[]): DiffLine[] {
  if (currentLines.length === 0) {
    return desiredLines.map((text) => ({ operation: "insert" as const, text }))
  }
  if (desiredLines.length === 0) {
    return currentLines.map((text) => ({ operation: "delete" as const, text }))
  }
  // R-0001017: bound the LCS allocation. Both lengths are at least one here,
  // so the comparison reflects the true (n+1)*(m+1) table dimensions closely
  // enough for the soft-cap purpose without overflowing `Number`.
  if ((currentLines.length + 1) * (desiredLines.length + 1) > MAX_DIFF_CELLS) {
    return buildFallbackLineDiff(currentLines, desiredLines)
  }
  const table = buildLcsTable(currentLines, desiredLines)
  return backtrackLcs({ currentLines, desiredLines, table })
}

type Hunk = {
  currentStart: number
  desiredStart: number
  lines: DiffLine[]
}

class HunkBuilder {
  private activeHunk: Hunk | null = null
  private currentLineNumber = 1
  private desiredLineNumber = 1
  private readonly hunks: Hunk[] = []
  private pendingContext: DiffLine[] = []
  private trailingContextRemaining = 0

  public constructor(private readonly contextLines: number) {}

  public addLine(line: DiffLine): void {
    if (line.operation === "context") {
      this.handleContextLine(line)
    } else {
      this.handleChangeLine(line)
    }
  }

  public finish(): Hunk[] {
    if (this.activeHunk != null) {
      this.hunks.push(this.activeHunk)
      this.activeHunk = null
    }
    return this.hunks
  }

  private handleChangeLine(line: DiffLine): void {
    if (this.activeHunk == null) {
      const leadingContext = this.pendingContext
      this.activeHunk = {
        currentStart: this.currentLineNumber - leadingContext.length,
        desiredStart: this.desiredLineNumber - leadingContext.length,
        lines: leadingContext,
      }
      this.pendingContext = []
    }
    this.activeHunk.lines.push(line)
    this.trailingContextRemaining = this.contextLines
    if (line.operation === "delete") this.currentLineNumber += 1
    else this.desiredLineNumber += 1
  }

  private handleContextLine(line: DiffLine): void {
    if (this.activeHunk != null && this.trailingContextRemaining > 0) {
      this.activeHunk.lines.push(line)
      this.trailingContextRemaining -= 1
      if (this.trailingContextRemaining === 0) {
        this.hunks.push(this.activeHunk)
        this.activeHunk = null
      }
    } else {
      this.pendingContext.push(line)
      if (this.pendingContext.length > this.contextLines) this.pendingContext.shift()
    }
    this.currentLineNumber += 1
    this.desiredLineNumber += 1
  }
}

function buildHunks(diff: DiffLine[], contextLines: number): Hunk[] {
  const builder = new HunkBuilder(contextLines)
  for (const line of diff) {
    builder.addLine(line)
  }
  return builder.finish()
}

function countHunkLines(hunk: Hunk): { current: number; desired: number } {
  let current = 0
  let desired = 0
  for (const line of hunk.lines) {
    if (line.operation === "context") {
      current += 1
      desired += 1
    } else if (line.operation === "delete") {
      current += 1
    } else {
      desired += 1
    }
  }
  return { current, desired }
}

function renderHunk(hunk: Hunk): string[] {
  const counts = countHunkLines(hunk)
  const header = `@@ -${hunk.currentStart},${counts.current} +${hunk.desiredStart},${counts.desired} @@`
  const rendered = [header]
  for (const line of hunk.lines) {
    switch (line.operation) {
      case "context": {
        rendered.push(` ${line.text}`)
        break
      }
      case "delete": {
        rendered.push(`-${line.text}`)
        break
      }
      case "insert": {
        rendered.push(`+${line.text}`)
        break
      }
    }
  }
  return rendered
}

/**
 * Build a unified diff between `current` and `desired`.
 *
 * @param current - The current (remote) content, multi-line string.
 * @param desired - The desired content the module would write, multi-line string.
 * @param options - Optional rendering controls.
 * @returns The unified diff text, including `---/+++/@@` headers, or `""` when
 *   both inputs are identical.
 */
export function buildUnifiedDiff(
  current: string,
  desired: string,
  options?: UnifiedDiffOptions
): string {
  // Normalize CRLF on both sides before comparison so a file persisted with
  // platform-native line endings does not show as drift when the desired
  // content uses LF (the writers always produce LF).
  const normalizedCurrent = normalizeLineEndings(current)
  const normalizedDesired = normalizeLineEndings(desired)
  if (normalizedCurrent === normalizedDesired) return ""
  const contextLines = Math.max(0, options?.contextLines ?? DEFAULT_CONTEXT_LINES)
  const currentLabel = options?.currentLabel ?? "current"
  const desiredLabel = options?.desiredLabel ?? "desired"

  const currentLines = splitLines(normalizedCurrent)
  const desiredLines = splitLines(normalizedDesired)
  const diff = computeLineDiff(currentLines, desiredLines)
  const hunks = buildHunks(diff, contextLines)

  const output: string[] = [`--- ${currentLabel}`, `+++ ${desiredLabel}`]
  for (const hunk of hunks) {
    output.push(...renderHunk(hunk))
  }
  return output.join("\n")
}

/**
 * Build the `_dryRunDetail` string surfaced by a module's `_applyDryRun` hook
 * when the diff cannot be produced because the inner code path threw. The
 * helper inspects the thrown value for a `code` property (mirrors `NodeJS.
 * ErrnoException` and the `CommandError` shape exposed by the SSH layer) and
 * folds it into the human-readable detail so operators see *why* the
 * dry-run could not compute a diff without leaking the verbatim error
 * message. When the input is `undefined` or has no usable code, the generic
 * `"(dry-run)"` marker is returned so the runner's fallback formatting still
 * applies.
 *
 * @param error - The value caught by the surrounding try/catch, if any.
 * @returns A short parenthesised detail string suitable for the
 *   `_dryRunDetail` field on `ModuleResult`.
 */
export function buildDryRunDetail(error?: unknown): string {
  if (error == null) return "(dry-run)"
  if (typeof error === "object" && "code" in error) {
    const { code } = error
    if (typeof code === "string" && code.length > 0) {
      return `(dry-run, diff unavailable: ${code})`
    }
    if (typeof code === "number") {
      return `(dry-run, diff unavailable: ${String(code)})`
    }
  }
  return "(dry-run)"
}

/**
 * Convenience helper for modules that compare a single scalar key (e.g. a
 * sysctl key or an env var) so the output is a tiny one-line diff instead of
 * a full unified-diff frame.
 *
 * @param key - The key being compared.
 * @param currentValue - The current scalar value as a string, or `null` when unset.
 * @param desiredValue - The desired scalar value as a string.
 * @returns A two-line `-key=value` / `+key=value` diff, or `""` when both
 *   values match.
 */
export function buildKeyValueDiff(
  key: string,
  currentValue: null | string,
  desiredValue: string
): string {
  if (currentValue === desiredValue) return ""
  const lines: string[] = []
  if (currentValue !== null) lines.push(`-${key} = ${currentValue}`)
  lines.push(`+${key} = ${desiredValue}`)
  return lines.join("\n")
}
