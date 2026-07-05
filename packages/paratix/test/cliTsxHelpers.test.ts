import { describe, expect, it } from "vitest"

import { isMissingTsxDependencyError } from "../src/cliTsxHelpers.js"

function moduleNotFoundError(message: string, code = "ERR_MODULE_NOT_FOUND"): Error {
  const error = new Error(message)
  Object.assign(error, { code })
  return error
}

describe("isMissingTsxDependencyError", () => {
  it("returns false for non-Error values", () => {
    expect(isMissingTsxDependencyError("boom")).toBe(false)
    expect(isMissingTsxDependencyError(null)).toBe(false)
    expect(isMissingTsxDependencyError(undefined)).toBe(false)
    expect(isMissingTsxDependencyError({ code: "ERR_MODULE_NOT_FOUND" })).toBe(false)
  })

  it("returns false when the error has no module-not-found code", () => {
    expect(isMissingTsxDependencyError(new Error("Cannot find package 'tsx'"))).toBe(false)
    expect(
      isMissingTsxDependencyError(moduleNotFoundError("Cannot find package 'tsx'", "EACCES"))
    ).toBe(false)
  })

  it("returns false when the missing specifier is a different dependency", () => {
    expect(
      isMissingTsxDependencyError(moduleNotFoundError("Cannot find package 'commander'"))
    ).toBe(false)
    expect(
      isMissingTsxDependencyError(moduleNotFoundError("Cannot find module './missing.js'"))
    ).toBe(false)
  })

  it("returns false when the message shape is unknown", () => {
    expect(isMissingTsxDependencyError(moduleNotFoundError("some unrelated loader failure"))).toBe(
      false
    )
  })

  it("detects the missing tsx package via 'Cannot find package'", () => {
    expect(isMissingTsxDependencyError(moduleNotFoundError("Cannot find package 'tsx'"))).toBe(true)
    expect(
      isMissingTsxDependencyError(moduleNotFoundError("Cannot find package 'tsx/esm/api'"))
    ).toBe(true)
  })

  it("detects the missing tsx module via 'Cannot find module'", () => {
    expect(
      isMissingTsxDependencyError(moduleNotFoundError('Cannot find module "tsx/esm/api"'))
    ).toBe(true)
  })

  it("accepts the legacy MODULE_NOT_FOUND code", () => {
    expect(
      isMissingTsxDependencyError(
        moduleNotFoundError("Cannot find package 'tsx'", "MODULE_NOT_FOUND")
      )
    ).toBe(true)
  })

  it("normalizes backslash separators before matching the loader path", () => {
    expect(
      isMissingTsxDependencyError(
        moduleNotFoundError("Cannot find module 'C:\\project\\node_modules\\tsx\\esm\\api'")
      )
    ).toBe(true)
  })
})
