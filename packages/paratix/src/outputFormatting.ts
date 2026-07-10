import { stripVTControlCharacters } from "node:util"

import type { ModuleStatus } from "./types.js"

type DisplayStatus = "waiting" | ModuleStatus

const PACKAGE_MODULE_SUFFIX_LENGTH = 2
const PACKAGE_COLUMN_GAP_WIDTH = 2
const DEFAULT_TERMINAL_COLUMNS = 100
const MIN_PACKAGE_COLUMNS_WIDTH = 24
const MIN_PACKAGE_COLUMN_WIDTH = 18
const MIN_ANIMATED_LINE_COLUMNS = 8
const ELAPSED_DISPLAY_THRESHOLD_MS = 1000
const MILLISECONDS_PER_SECOND = 1000
const MILLISECONDS_PER_MINUTE = 60_000
const SECONDS_PER_MINUTE = 60

export type DisplayModule = {
  detail?: string
  detailLines: string[]
  name: string
}

function splitPackageModuleName(name: string): { packages: string[]; summaryName: string } | null {
  for (const prefix of ["package.installed: ", "package.absent: "]) {
    if (!name.startsWith(prefix)) continue

    const packages = name
      .slice(prefix.length)
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean)
    if (packages.length === 0) return null

    return {
      packages,
      summaryName: prefix.slice(0, -PACKAGE_MODULE_SUFFIX_LENGTH),
    }
  }

  return null
}

function getPackageColumns(parameters: {
  continuationIndentWidth: number
  packages: string[]
  terminalColumns?: number
}): string[] {
  if (parameters.packages.length <= 1) return parameters.packages

  const availableWidth = Math.max(
    (parameters.terminalColumns ?? DEFAULT_TERMINAL_COLUMNS) - parameters.continuationIndentWidth,
    MIN_PACKAGE_COLUMNS_WIDTH
  )
  const widestPackage = Math.max(...parameters.packages.map((entry) => entry.length))
  const columnWidth = Math.max(widestPackage + PACKAGE_COLUMN_GAP_WIDTH, MIN_PACKAGE_COLUMN_WIDTH)
  const columnCount = Math.max(Math.floor(availableWidth / columnWidth), 1)
  const rowCount = Math.ceil(parameters.packages.length / columnCount)

  return Array.from({ length: rowCount }, (_row, rowIndex) =>
    Array.from({ length: columnCount }, (_column, columnIndex) => {
      const packageIndex = rowIndex + columnIndex * rowCount
      const packageName = parameters.packages.at(packageIndex)
      if (packageName == null) return ""
      const isLastVisibleColumn =
        columnIndex === columnCount - 1 || packageIndex + rowCount >= parameters.packages.length
      return isLastVisibleColumn ? packageName : packageName.padEnd(columnWidth)
    })
      .filter(Boolean)
      .join("")
  )
}

function getPackageSummaryDetail(packageCount: number, detail?: string): string {
  const packageLabel = packageCount === 1 ? "1 package" : `${packageCount} packages`
  return detail == null ? packageLabel : `${packageLabel} · ${detail}`
}

/**
 * Format a module's elapsed run time as an adaptive, human-readable suffix.
 *
 * Returns `undefined` below a 1-second threshold so very fast checks stay free
 * of any time annotation. Under 60 seconds the value is rendered in seconds with
 * a single decimal place (e.g. `3.2s`); from 60 seconds on it switches to whole
 * minutes and seconds with a zero-padded seconds field (e.g. `1m 05s`). Negative
 * or non-finite inputs are treated defensively as below the threshold.
 *
 * The final result line derives its value from the same function independently
 * of the live spinner frames, so a module that crosses the 1-second threshold
 * only just before finishing still shows a static time on its result line even
 * if no live frame ever rendered one.
 *
 * @param elapsedMs - The elapsed time in milliseconds.
 * @returns The formatted elapsed text, or `undefined` when nothing should show.
 */
export function formatModuleElapsed(elapsedMs: number): string | undefined {
  if (!Number.isFinite(elapsedMs) || elapsedMs < ELAPSED_DISPLAY_THRESHOLD_MS) return undefined

  if (elapsedMs < MILLISECONDS_PER_MINUTE) {
    return `${(elapsedMs / MILLISECONDS_PER_SECOND).toFixed(1)}s`
  }

  const totalSeconds = Math.floor(elapsedMs / MILLISECONDS_PER_SECOND)
  const minutes = Math.floor(totalSeconds / SECONDS_PER_MINUTE)
  const seconds = totalSeconds % SECONDS_PER_MINUTE
  return `${minutes}m ${String(seconds).padStart(2, "0")}s`
}

export function fitAnimatedModuleLine(line: string, columns?: number): string {
  if (columns === undefined || columns < MIN_ANIMATED_LINE_COLUMNS) return line

  const plainLine = stripVTControlCharacters(line)
  if (plainLine.length < columns) return line

  return `${plainLine.slice(0, columns - 1)}\u2026`
}

export function formatDisplayModule(parameters: {
  continuationIndentWidth: number
  detail?: string
  name: string
  status: DisplayStatus
  terminalColumns?: number
}): DisplayModule {
  const packageModule = splitPackageModuleName(parameters.name)
  if (packageModule == null) {
    return {
      detail: parameters.detail,
      detailLines: [],
      name: parameters.name,
    }
  }

  return {
    detail: getPackageSummaryDetail(packageModule.packages.length, parameters.detail),
    detailLines:
      parameters.status === "waiting"
        ? []
        : getPackageColumns({
            continuationIndentWidth: parameters.continuationIndentWidth,
            packages: packageModule.packages,
            terminalColumns: parameters.terminalColumns,
          }),
    name: packageModule.summaryName,
  }
}
