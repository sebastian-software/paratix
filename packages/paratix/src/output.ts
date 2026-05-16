/* eslint-disable max-lines -- CLI output rendering is intentionally kept together */
import { inspect } from "node:util"
import pc from "picocolors"

import type { ModuleStatus } from "./types.js"

import { fitAnimatedModuleLine, formatDisplayModule } from "./outputFormatting.js"
import { maskRegisteredSecrets } from "./secretSink.js"
import { CommandError } from "./sshHelpers.js"

// R-0000580: bounds for `util.inspect` when rendering non-Error cause values so
// a runaway plain object cannot dump unbounded text into stderr.
const CAUSE_INSPECT_DEPTH = 2
const CAUSE_INSPECT_MAX_STRING_LENGTH = 1024

const MODULE_NAME_WIDTH = 56
const MIN_MODULE_NAME_WIDTH = 12
const OUTPUT_INDENT_UNIT = "  "
const SPINNER_FRAME_INTERVAL_MS = 80
const SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
type DisplayStatus = "waiting" | ModuleStatus

const STATUS_ICONS: Record<DisplayStatus, string> = {
  changed: pc.yellow("\u21ba"),
  failed: pc.red("\u2717"),
  ok: pc.green("\u2713"),
  skipped: pc.dim("\u2298"),
  waiting: pc.cyan("\u23f8"),
}

const CLI_HEADER_LINES = [
  "                        _   _      ",
  "                       | | (_)     ",
  "  _ __   __ _ _ __ __ _| |_ ___  __",
  " | '_ \\ / _` | '__/ _` | __| \\ \\/ /",
  " | |_) | (_| | | | (_| | |_| |>  < ",
  " | .__/ \\__,_|_|  \\__,_|\\__|_/_/\\_\\",
  " | |                               ",
  " |_|  ",
]

type ActiveSpinner = {
  detail?: string
  frameIndex: number
  interval: NodeJS.Timeout
}

let activeSpinner: ActiveSpinner | null = null
let activeRecipeGuideDepths: number[] = []
let pendingRecipeClosureGuideDepths: number[] = []
let recipeOutputDepth = -1

export function renderCliHeader(version: string): string {
  const versionText = pc.dim(`v${version}`)
  return `${pc.cyan(CLI_HEADER_LINES.join("\n"))}${versionText}\n`
}

export function printCliHeader(version: string): void {
  console.log(renderCliHeader(version))
}

function supportsAnimatedModuleOutput(): boolean {
  return (
    process.stdout.isTTY &&
    typeof process.stdout.clearLine === "function" &&
    typeof process.stdout.cursorTo === "function"
  )
}

function getModuleIcon(status: DisplayStatus, waitingFrame?: string): string {
  return status === "waiting" ? pc.cyan(waitingFrame ?? "|") : STATUS_ICONS[status]
}

function getModuleStatusText(status: DisplayStatus): string {
  switch (status) {
    case "changed": {
      return pc.yellow(status)
    }
    case "failed": {
      return pc.red(status)
    }
    case "ok": {
      return pc.green(status)
    }
    case "skipped": {
      return pc.dim(status)
    }
    case "waiting": {
      return pc.cyan("running")
    }
  }
}

function getCurrentOutputDepth(): number {
  return Math.max(recipeOutputDepth, 0)
}

function getGuideDot(depth: number): string {
  return depth % 2 === 0 ? pc.gray("·") : pc.cyan("·")
}

function buildGuideIndent(
  baseIndent: string,
  options?: {
    activeGuideDepths?: number[]
    colorize?: boolean
    extraGuideDepths?: number[]
  }
): string {
  const indentCharacters = Array.from(baseIndent)
  const guideDepths = [
    ...(options?.activeGuideDepths ?? activeRecipeGuideDepths),
    ...(options?.extraGuideDepths ?? []),
  ]

  for (const guideDepth of guideDepths) {
    const guideCharacterIndex = OUTPUT_INDENT_UNIT.length * (guideDepth + 1)
    if (guideCharacterIndex >= indentCharacters.length) continue
    indentCharacters[guideCharacterIndex] =
      options?.colorize === false ? "·" : getGuideDot(guideDepth)
  }

  return indentCharacters.join("")
}

function clearPendingRecipeClosureGuides(): void {
  pendingRecipeClosureGuideDepths = []
}

function getModuleIndent(): string {
  if (recipeOutputDepth < 0) {
    return OUTPUT_INDENT_UNIT
  }

  return OUTPUT_INDENT_UNIT.repeat(getCurrentOutputDepth() + 2)
}

function getRecipeHeaderIndent(): string {
  if (recipeOutputDepth < 0) return ""
  return OUTPUT_INDENT_UNIT.repeat(getCurrentOutputDepth() + 1)
}

function getErrorIndent(): string {
  return `${getModuleIndent()}│ `
}

function getContinuationIndent(): string {
  return `${getModuleIndent()}   `
}

export async function withRecipeOutputScope<T>(
  scopedOperation: () => Promise<T> | T
): Promise<T> {
  recipeOutputDepth += 1
  try {
    return await scopedOperation()
  } finally {
    activeRecipeGuideDepths = activeRecipeGuideDepths.filter((depth) => depth !== recipeOutputDepth)
    pendingRecipeClosureGuideDepths = [recipeOutputDepth]
    recipeOutputDepth -= 1
  }
}

function renderModuleLine(parameters: {
  detail?: string
  extraGuideDepths?: number[]
  name: string
  status: DisplayStatus
  waitingFrame?: string
}): string {
  const { detail, extraGuideDepths = [], name, status, waitingFrame } = parameters
  const baseIndent = getModuleIndent()
  const indent = buildGuideIndent(baseIndent, { extraGuideDepths })
  const icon = getModuleIcon(status, waitingFrame)
  const statusText = getModuleStatusText(status)
  const detailSuffix = detail == null ? "" : `  ${pc.dim(detail)}`
  const alignedNameWidth = Math.max(MODULE_NAME_WIDTH - baseIndent.length, MIN_MODULE_NAME_WIDTH)
  return `${indent}${icon}  ${name.padEnd(alignedNameWidth)}  ${statusText}${detailSuffix}`
}

function writeAnimatedModuleLine(line: string): void {
  process.stdout.clearLine(0)
  process.stdout.cursorTo(0)
  process.stdout.write(fitAnimatedModuleLine(line, process.stdout.columns))
}

function stopAnimatedModuleLine(clearCurrentLine = false): void {
  if (activeSpinner == null) return

  clearInterval(activeSpinner.interval)
  activeSpinner = null

  if (clearCurrentLine && supportsAnimatedModuleOutput()) {
    process.stdout.clearLine(0)
    process.stdout.cursorTo(0)
  }
}

export function stopLiveModuleOutput(clearCurrentLine = false): void {
  stopAnimatedModuleLine(clearCurrentLine)
}

export function startModuleSpinner(name: string, detail?: string): void {
  if (!supportsAnimatedModuleOutput()) return

  clearPendingRecipeClosureGuides()
  stopAnimatedModuleLine()
  const maskedName = maskRegisteredSecrets(name)
  const maskedDetail = detail == null ? undefined : maskRegisteredSecrets(detail)
  const displayModule = formatDisplayModule({
    continuationIndentWidth: getContinuationIndent().length,
    detail: maskedDetail,
    name: maskedName,
    status: "waiting",
    terminalColumns: process.stdout.columns,
  })

  const spinner: ActiveSpinner = {
    detail: displayModule.detail,
    frameIndex: 0,
    interval: setInterval(() => {
      spinner.frameIndex = (spinner.frameIndex + 1) % SPINNER_FRAMES.length
      writeAnimatedModuleLine(
        renderModuleLine({
          detail: spinner.detail,
          name: displayModule.name,
          status: "waiting",
          waitingFrame: SPINNER_FRAMES[spinner.frameIndex],
        })
      )
    }, SPINNER_FRAME_INTERVAL_MS),
  }
  // Avoid keeping the event loop alive solely for the spinner timer:
  // if stopAnimatedModuleLine/stopLiveModuleOutput is missed in an
  // unhappy-path (uncaughtException), the process should still be able
  // to exit. Mirrors the pattern used by sleepRespectingShutdown in runner.ts.
  if (typeof spinner.interval.unref === "function") spinner.interval.unref()

  activeSpinner = spinner
  writeAnimatedModuleLine(
    renderModuleLine({
      detail: displayModule.detail,
      name: displayModule.name,
      status: "waiting",
      waitingFrame: SPINNER_FRAMES[0],
    })
  )
}

export function resetLiveOutputForTests(): void {
  stopAnimatedModuleLine()
  activeRecipeGuideDepths = []
  clearPendingRecipeClosureGuides()
  recipeOutputDepth = -1
}

/**
 * Print a bold, colored header line marking the start of a recipe run.
 * @param name - The recipe or server name to display.
 */
export function printRecipeHeader(name: string): void {
  stopAnimatedModuleLine(true)
  clearPendingRecipeClosureGuides()
  const header = pc.bold(pc.blue(`[${name}]`))
  console.log(`${buildGuideIndent(getRecipeHeaderIndent())}${header}`)
  if (recipeOutputDepth >= 0) {
    activeRecipeGuideDepths = [...activeRecipeGuideDepths, recipeOutputDepth]
  }
}

export function printRunContext(parameters: {
  dryRun: boolean
  host: string
  name: string
  ports: number[]
}): void {
  const mode = parameters.dryRun ? pc.yellow("dry-run") : pc.green("apply")
  const ports = parameters.ports.join(", ")
  console.log(
    pc.dim(`Run ${parameters.name} · host ${parameters.host} · ports ${ports} · mode ${mode}`)
  )
}

function printRenderedModuleResult(parameters: {
  detail?: string
  extraGuideDepths?: number[]
  name: string
  status: DisplayStatus
}): void {
  const extraGuideDepths = parameters.extraGuideDepths ?? []
  const maskedName = maskRegisteredSecrets(parameters.name)
  const maskedDetail =
    parameters.detail == null ? undefined : maskRegisteredSecrets(parameters.detail)
  const displayModule = formatDisplayModule({
    continuationIndentWidth: `${buildGuideIndent(
      OUTPUT_INDENT_UNIT.repeat(Math.max(getCurrentOutputDepth() + 2, 1)),
      { extraGuideDepths }
    )}   `.length,
    detail: maskedDetail,
    name: maskedName,
    status: parameters.status,
    terminalColumns: process.stdout.columns,
  })
  const line = renderModuleLine({
    detail: displayModule.detail,
    extraGuideDepths,
    name: displayModule.name,
    status: parameters.status,
  })

  if (supportsAnimatedModuleOutput() && activeSpinner != null) {
    stopAnimatedModuleLine()
    writeAnimatedModuleLine(line)
    process.stdout.write("\n")
    for (const detailLine of displayModule.detailLines) {
      process.stdout.write(
        `${buildGuideIndent(getContinuationIndent(), { extraGuideDepths })}${pc.dim(detailLine)}\n`
      )
    }
    return
  }

  console.log(line)
  for (const detailLine of displayModule.detailLines) {
    console.log(
      `${buildGuideIndent(getContinuationIndent(), { extraGuideDepths })}${pc.dim(detailLine)}`
    )
  }
}

/**
 * Print a single module result row with a status icon, name, and colored status label.
 *
 * @param name - The module name shown in the left column.
 * @param status - One of the known status strings (`ok`, `changed`, `skipped`, `failed`).
 * @param detail - Optional short detail appended in dim text after the status.
 */
export function printModuleResult(name: string, status: DisplayStatus, detail?: string): void {
  clearPendingRecipeClosureGuides()
  printRenderedModuleResult({ detail, name, status })
}

export function printRecipeModuleResult(name: string, status: DisplayStatus, detail?: string): void {
  printRenderedModuleResult({
    detail,
    extraGuideDepths: pendingRecipeClosureGuideDepths,
    name,
    status,
  })
  clearPendingRecipeClosureGuides()
}

/**
 * Print captured stderr and stdout from a failed command in a red bordered block.
 * Outputs nothing if both streams are empty.
 *
 * @param stdout - Captured standard output of the failed command.
 * @param stderr - Captured standard error of the failed command.
 */
export function printCommandError(stdout: string, stderr: string): void {
  const lines: string[] = []
  if (stderr.trim()) {
    lines.push(...stderr.trim().split("\n"))
  }
  if (stdout.trim()) {
    lines.push(...stdout.trim().split("\n"))
  }
  if (lines.length > 0) {
    console.error(pc.red(`${getErrorIndent()}Error output:`))
    for (const line of lines) {
      console.error(pc.red(`${getErrorIndent()}${line}`))
    }
  }
}

/**
 * Print the full (untruncated) stdout and stderr of a failed command.
 * Used in verbose mode to show the complete output that was truncated in the error message.
 *
 * @param stdout - Full standard output of the failed command.
 * @param stderr - Full standard error of the failed command.
 */
export function printVerboseCommandError(stdout: string, stderr: string): void {
  if (stderr.trim()) {
    console.error(pc.red(`${getErrorIndent()}Full stderr:`))
    for (const line of stderr.trim().split("\n")) {
      console.error(pc.red(`${getErrorIndent()}${line}`))
    }
  }
  if (stdout.trim()) {
    console.error(pc.red(`${getErrorIndent()}Full stdout:`))
    for (const line of stdout.trim().split("\n")) {
      console.error(pc.red(`${getErrorIndent()}${line}`))
    }
  }
}

function printVerboseErrorBlock(label: string, content: string): void {
  if (!content.trim()) {
    return
  }

  console.error(pc.red(`${getErrorIndent()}${label}`))
  for (const line of content.trim().split("\n")) {
    console.error(pc.red(`${getErrorIndent()}${line}`))
  }
}

function getErrorCause(error: Error): unknown {
  return (error as { cause?: unknown } & Error).cause
}

function printVerboseErrorCause(
  cause: unknown,
  depth: number,
  visitedCauses: WeakSet<Error>
): void {
  const label = `Cause ${depth}:`
  if (cause instanceof Error) {
    if (visitedCauses.has(cause)) {
      printVerboseErrorBlock(label, "<cycle detected>")
      return
    }
    visitedCauses.add(cause)
    const stack = cause.stack?.trim() ?? ""
    const stackOrMessage = stack.length > 0 ? stack : String(cause)
    printVerboseErrorBlock(label, maskRegisteredSecrets(stackOrMessage))
    const nestedCause = getErrorCause(cause)
    if (nestedCause !== undefined) {
      printVerboseErrorCause(nestedCause, depth + 1, visitedCauses)
    }
    return
  }

  printVerboseErrorBlock(label, maskRegisteredSecrets(String(cause)))
}

function printVerboseGenericError(error: Error): void {
  const stack = error.stack?.trim() ?? ""
  const stackOrMessage = stack.length > 0 ? stack : String(error)
  // R-0000041: redact any registered secrets that may have flowed into the
  // stack trace through Error wrapping or third-party libraries before it
  // reaches stderr.
  printVerboseErrorBlock("Full stack:", maskRegisteredSecrets(stackOrMessage))
  const cause = getErrorCause(error)
  if (cause !== undefined) {
    // Track every Error seen while walking the cause chain to detect cycles
    // produced by third-party error wrapping (e.g. err.cause === err) so the
    // recursion always terminates.
    const visitedCauses = new WeakSet<Error>()
    visitedCauses.add(error)
    printVerboseErrorCause(cause, 1, visitedCauses)
  }
}

/**
 * Format the textual representation of a single cause-chain link. `Error`
 * values surface their message; other values are rendered through
 * {@link inspect} with bounded depth/string length so primitives and plain
 * objects still carry diagnostic context without dumping unbounded text.
 */
function formatCauseValue(cause: unknown): string {
  if (cause instanceof Error) return cause.message
  // R-0000580: replace `String(cause)` with `util.inspect` so plain objects
  // produce useful output ("[object Object]" → `{ key: "…" }`) and the result
  // is capped via depth/string-length bounds.
  return inspect(cause, {
    depth: CAUSE_INSPECT_DEPTH,
    maxStringLength: CAUSE_INSPECT_MAX_STRING_LENGTH,
  })
}

/**
 * Walk the `Error.cause` chain of `error` and emit one `Cause: …` block per
 * level on stderr. Used by {@link printCommandFailure} so generic (non-
 * {@link CommandError}) failures surface their wrapped root cause even in
 * non-verbose mode — without this, only `Error.message` would reach stderr
 * and the actual reason (a wrapped `ECONNREFUSED`, a parse failure, …)
 * would stay hidden until the operator re-ran with `--verbose`.
 *
 * The walker keeps a {@link WeakSet} of already-visited `Error` references
 * so a self-referencing or cyclic `cause` chain — which a misbehaving
 * library can construct — cannot loop forever.
 *
 * @param error - The root `Error` whose `.cause` chain should be printed.
 */
function printCauseChain(error: Error): void {
  const visited = new WeakSet<Error>()
  visited.add(error)
  let cause = getErrorCause(error)
  while (cause !== undefined) {
    if (cause instanceof Error) {
      if (visited.has(cause)) return
      visited.add(cause)
    }
    console.error(pc.red(`${getErrorIndent()}Cause: ${maskRegisteredSecrets(formatCauseValue(cause))}`))
    // R-0000580: when a `CommandError` appears as a cause it carries the full
    // stdout/stderr of the failed remote command. Emit those streams the same
    // way `printVerboseCommandError` does so the operator does not lose the
    // command output once it has been wrapped into an outer error. Stdout and
    // stderr go through `maskRegisteredSecrets` like the existing verbose path
    // in `printCommandFailure`.
    if (cause instanceof CommandError) {
      printVerboseCommandError(
        maskRegisteredSecrets(cause.fullStdout),
        maskRegisteredSecrets(cause.fullStderr)
      )
    }
    cause = cause instanceof Error ? getErrorCause(cause) : undefined
  }
}

/**
 * Print the error message of a failed command and, when verbose mode is active
 * and the error is a {@link CommandError}, the full untruncated output.
 *
 * R-0000041: every string written to stderr is passed through
 * {@link maskRegisteredSecrets} so resolved op values, sudo passwords, user
 * password hashes, and download URL tokens never leak through generic
 * `Error.message` or stack-trace paths. Modules register their secrets via
 * `secretSink.registerSecret` (or `withRegisteredSecrets`) for the duration
 * of the work that produces them.
 *
 * @param error - The caught error value.
 * @param verbose - Whether to show full stdout/stderr.
 */
export function printCommandFailure(error: unknown, verbose: boolean): void {
  if (verbose && error instanceof CommandError) {
    // Print only the exit-code line, skip the truncated output and hint
    const summaryLine = error.message.split("\n")[0]
    printCommandError("", maskRegisteredSecrets(summaryLine))
    printVerboseCommandError(
      maskRegisteredSecrets(error.fullStdout),
      maskRegisteredSecrets(error.fullStderr)
    )
    return
  }

  printCommandError("", maskRegisteredSecrets(String(error)))
  if (error instanceof Error) {
    if (!(error instanceof CommandError)) {
      // R-0000520: for generic Errors, surface the Error.cause chain even
      // without --verbose so the wrapped root cause (ECONNREFUSED behind a
      // wrapper Error, a parser failure behind a domain Error, …) reaches
      // stderr instead of being hidden behind the top-level message. Cycle-
      // safe via WeakSet. CommandError has its own structured diagnostic
      // surface (full stdout/stderr) and is handled in verbose mode above.
      printCauseChain(error)
    }
    if (verbose) {
      printVerboseGenericError(error)
    }
  }
}

/**
 * Print a run summary line with counts for each status category.
 *
 * @param stats - Aggregated counts from the completed run.
 * @param stats.changed - Number of modules that changed state.
 * @param stats.ok - Number of modules already in desired state.
 * @param stats.skipped - Number of modules skipped.
 * @param stats.failed - Number of modules that failed.
 * @param stats.signals - Number of signals triggered.
 */
export function printSummary(stats: {
  changed: number
  failed: number
  ok: number
  signals: number
  skipped: number
}): void {
  stopAnimatedModuleLine(true)
  const parts = [
    pc.yellow(`${stats.changed} changed`),
    pc.green(`${stats.ok} ok`),
    pc.dim(`${stats.skipped} skipped`),
    stats.failed > 0 ? pc.red(`${stats.failed} failed`) : `${stats.failed} failed`,
    pc.cyan(`${stats.signals} signals triggered`),
  ]
  console.log(`\n${parts.join(pc.dim(" \u00b7 "))}`)
}
