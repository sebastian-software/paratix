import { stripVTControlCharacters } from "node:util"

import type { ModuleStatus } from "./types.js"

type DisplayStatus = "waiting" | ModuleStatus

const PACKAGE_MODULE_SUFFIX_LENGTH = 2
const PACKAGE_COLUMN_GAP_WIDTH = 2
const DEFAULT_TERMINAL_COLUMNS = 100
const MIN_PACKAGE_COLUMNS_WIDTH = 24
const MIN_PACKAGE_COLUMN_WIDTH = 18
const MIN_ANIMATED_LINE_COLUMNS = 8

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
