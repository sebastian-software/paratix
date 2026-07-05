import { describe, expect, it, vi } from "vitest"

import type { ExecResult, ModuleResult } from "../src/types.js"

import { failed, failedCommand, withRollbackFailure } from "../src/moduleFailure.js"
import { CommandError } from "../src/sshHelpers.js"

function execResult(overrides: Partial<ExecResult>): ExecResult {
  return { code: 1, stderr: "", stdout: "", ...overrides }
}

function asCommandError(error: Error | undefined): CommandError {
  if (!(error instanceof CommandError)) {
    throw new TypeError("expected the failure error to be a CommandError")
  }
  return error
}

describe("failed", () => {
  it("wraps the message in a failed ModuleResult", () => {
    const result = failed("boom")
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(result.error?.message).toBe("boom")
  })
})

describe("failedCommand", () => {
  it("renders the exit code and the first non-empty stderr line", () => {
    const result = failedCommand("apt-get failed", execResult({ code: 100, stderr: "E: broken" }))
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(CommandError)
    expect(result.error?.message).toBe("apt-get failed (exit code 100)\nE: broken")
  })

  it("skips leading blank lines when picking the detail line", () => {
    const result = failedCommand("cmd failed", execResult({ stderr: "\n   \nreal error\nsecond" }))
    expect(result.error?.message).toBe("cmd failed (exit code 1)\nreal error")
  })

  it("falls back to stdout when stderr is empty", () => {
    const result = failedCommand("cmd failed", execResult({ stderr: "", stdout: "stdout detail" }))
    expect(result.error?.message).toBe("cmd failed (exit code 1)\nstdout detail")
  })

  it("omits the detail line when both streams are blank", () => {
    const result = failedCommand("cmd failed", execResult({ stderr: "  ", stdout: "" }))
    expect(result.error?.message).toBe("cmd failed (exit code 1)")
  })

  it("masks every secret variant in the rendered message and stored output", () => {
    const result = failedCommand(
      "upload failed",
      execResult({ stderr: "token=s3cr3t leaked", stdout: "url s3cr3t" }),
      ["s3cr3t"]
    )
    const error = asCommandError(result.error)
    expect(error.message).not.toContain("s3cr3t")
    expect(error.message).toContain("[REDACTED]")
    expect(error.fullStderr).not.toContain("s3cr3t")
    expect(error.fullStdout).not.toContain("s3cr3t")
  })

  it("does not mask when the secrets list is empty", () => {
    const result = failedCommand("cmd failed", execResult({ stderr: "plain" }), [])
    expect(result.error?.message).toBe("cmd failed (exit code 1)\nplain")
  })
})

describe("withRollbackFailure", () => {
  const failure: ModuleResult = failed("primary failure")

  it("returns the original failure when the rollback succeeds", async () => {
    const rollback = vi.fn().mockResolvedValue(undefined)
    const result = await withRollbackFailure(failure, rollback)
    expect(result).toBe(failure)
    expect(rollback).toHaveBeenCalledOnce()
  })

  it("appends the rollback error message when the rollback throws an Error", async () => {
    const rollback = vi.fn().mockRejectedValue(new Error("cleanup exploded"))
    const result = await withRollbackFailure(failure, rollback)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toBe("primary failure\nrollback failed: cleanup exploded")
  })

  it("stringifies non-Error rollback rejections", async () => {
    const rollback = vi.fn().mockRejectedValue("string reason")
    const result = await withRollbackFailure(failure, rollback)
    expect(result.error?.message).toBe("primary failure\nrollback failed: string reason")
  })

  it("uses the fallback message when the failure carries no error", async () => {
    const noErrorFailure: ModuleResult = { status: "failed" }
    const rollback = vi.fn().mockRejectedValue(new Error("cleanup exploded"))
    const result = await withRollbackFailure(noErrorFailure, rollback, "default context")
    expect(result.error?.message).toBe("default context\nrollback failed: cleanup exploded")
  })
})
