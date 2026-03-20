import type { ExecResult, ModuleResult } from "./types.js"

import { CommandError } from "./sshHelpers.js"

function firstNonEmptyLine(text: string): null | string {
  for (const line of text.split("\n")) {
    const trimmed = line.trim()
    if (trimmed.length > 0) return trimmed
  }
  return null
}

export function failed(message: string): ModuleResult {
  return { error: new Error(message), status: "failed" }
}

export function failedCommand(message: string, result: ExecResult): ModuleResult {
  const detail = firstNonEmptyLine(result.stderr) ?? firstNonEmptyLine(result.stdout)
  const summary = `${message} (exit code ${String(result.code)})`
  const errorMessage = detail == null ? summary : `${summary}\n${detail}`
  return {
    error: new CommandError(errorMessage, result.stdout, result.stderr),
    status: "failed",
  }
}
