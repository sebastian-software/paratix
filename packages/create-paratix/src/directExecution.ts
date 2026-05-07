import { realpathSync } from "node:fs"
import { resolve } from "node:path"
import { fileURLToPath } from "node:url"

function normalizeExecutionPath(path: string): string {
  const resolvedPath = resolve(path)
  try {
    return realpathSync.native(resolvedPath)
  } catch {
    return resolvedPath
  }
}

export function isDirectExecution(moduleUrl: string, argv1: null | string | undefined): boolean {
  if (argv1 == null) return false
  try {
    return normalizeExecutionPath(fileURLToPath(moduleUrl)) === normalizeExecutionPath(argv1)
  } catch {
    return false
  }
}
