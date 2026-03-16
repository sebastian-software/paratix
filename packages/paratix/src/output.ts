import pc from "picocolors"

import { CommandError } from "./sshHelpers.js"

const MODULE_NAME_WIDTH = 36

const STATUS_ICONS: Record<string, string> = {
  changed: pc.yellow("\u21ba"),
  failed: pc.red("\u2717"),
  ok: pc.green("\u2713"),
  skipped: pc.dim("\u2298"),
  waiting: pc.cyan("\u23f8"),
}

/**
 * Print a bold, colored header line marking the start of a recipe run.
 * @param name - The recipe or server name to display.
 */
export function printRecipeHeader(name: string): void {
  const header = pc.bold(pc.blue(`[${name}]`))
  console.log(`\n${header}`)
}

/**
 * Print a single module result row with a status icon, name, and colored status label.
 *
 * @param name - The module name shown in the left column.
 * @param status - One of the known status strings (`ok`, `changed`, `skipped`, `failed`).
 * @param detail - Optional short detail appended in dim text after the status.
 */
export function printModuleResult(name: string, status: string, detail?: string): void {
  const icon = STATUS_ICONS[status] ?? " "
  let statusText: string
  switch (status) {
    case "changed": {
      statusText = pc.yellow(status)

      break
    }
    case "failed": {
      statusText = pc.red(status)

      break
    }
    case "ok": {
      statusText = pc.green(status)

      break
    }
    default: {
      statusText = pc.dim(status)
    }
  }

  const detailSuffix = detail == null ? "" : `  ${pc.dim(detail)}`
  console.log(`  ${icon}  ${name.padEnd(MODULE_NAME_WIDTH)}${statusText}${detailSuffix}`)
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
    console.log(pc.red("  \u2502 Error output:"))
    for (const line of lines) {
      console.log(pc.red(`  \u2502 ${line}`))
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
    console.log(pc.red("  │ Full stderr:"))
    for (const line of stderr.trim().split("\n")) {
      console.log(pc.red(`  │ ${line}`))
    }
  }
  if (stdout.trim()) {
    console.log(pc.red("  │ Full stdout:"))
    for (const line of stdout.trim().split("\n")) {
      console.log(pc.red(`  │ ${line}`))
    }
  }
}

/**
 * Print the error message of a failed command and, when verbose mode is active
 * and the error is a {@link CommandError}, the full untruncated output.
 *
 * @param error - The caught error value.
 * @param verbose - Whether to show full stdout/stderr.
 */
export function printCommandFailure(error: unknown, verbose: boolean): void {
  if (verbose && error instanceof CommandError) {
    // Print only the exit-code line, skip the truncated output and hint
    const summaryLine = error.message.split("\n")[0]
    printCommandError("", summaryLine)
    printVerboseCommandError(error.fullStdout, error.fullStderr)
  } else {
    printCommandError("", String(error))
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
  const parts = [
    pc.yellow(`${stats.changed} changed`),
    pc.green(`${stats.ok} ok`),
    pc.dim(`${stats.skipped} skipped`),
    stats.failed > 0 ? pc.red(`${stats.failed} failed`) : `${stats.failed} failed`,
    pc.cyan(`${stats.signals} signals triggered`),
  ]
  console.log(`\n${parts.join(pc.dim(" \u00b7 "))}`)
}
