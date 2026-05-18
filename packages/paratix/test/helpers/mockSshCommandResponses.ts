import type { ExecOptions, ExecResult, SshConnection } from "../../src/types.js"

import {
  isFlagLockHolderReadback,
  isFlagLockInternalSuccessCommand,
  isFlagLockReclaimProbe,
  MOCK_FLAG_LOCK_HOLDER_TOKEN,
} from "./mockSshFlagLock.js"

export type MockResponses = Record<string, Partial<ExecResult>>
export type MockResponseStub = { command: RegExp | string; result: Partial<ExecResult> }

export type MockCommandOptions = {
  allowFlagLockInternalDefaults?: boolean
  /**
   * When `true`, explicit default results may answer otherwise unstubbed
   * commands. Leave unset to keep strict mocks fail-closed even when defaults
   * are configured.
   */
  allowUnstubbedDefaults?: boolean
  allowUnstubbedExec?: string[]
  allowUnstubbedOutput?: string[]
  allowUnstubbedTest?: string[]
  /**
   * Result returned by `ssh.exec()` for unstubbed commands.
   */
  defaultExecResult?: "throw" | Partial<ExecResult>
  /**
   * Result returned by `ssh.output()` for unstubbed commands.
   */
  defaultOutputResult?: string
  /** Result returned by `ssh.test()` for unstubbed commands. */
  defaultTestResult?: boolean
  /**
   * When `false`, `ssh.exec()` and `ssh.output()` return non-zero results by
   * default. Leave unset for production-like command failure propagation.
   */
  rejectNonZeroExit?: boolean
  /**
   * Explicit command stubs matched after exact responses and before any
   * fallback defaults or allowlists.
   */
  responseStubs?: MockResponseStub[]
  strict?: boolean
  /**
   * When `true`, log a `console.warn` for every unstubbed `ssh.test()` call so
   * test authors can audit silent permissive matches. Off by default to keep
   * existing test runs quiet.
   */
  warnOnUnstubbedTest?: boolean
}

/** Recorded `ssh.exec` invocation: the command string plus the options it received. */
export type ExecCall = { command: string; options: ExecOptions | undefined }

function isAllowed(command: string, allowed?: string[]): boolean {
  return allowed?.includes(command) ?? false
}

function buildUnstubbedCommandError(kind: "exec" | "output" | "test", command: string): Error {
  return new Error(`createMockSsh: unstubbed ${kind} call: ${command}`)
}

function getAllowlistForKind(
  kind: "exec" | "output" | "test",
  options: MockCommandOptions | undefined
): string[] | undefined {
  if (kind === "exec") return options?.allowUnstubbedExec
  if (kind === "output") return options?.allowUnstubbedOutput
  return options?.allowUnstubbedTest
}

function hasExplicitDefaultForKind(
  kind: "exec" | "output" | "test",
  options: MockCommandOptions | undefined
): boolean {
  if (kind === "exec") return options?.defaultExecResult !== undefined
  if (kind === "output") return options?.defaultOutputResult !== undefined
  return options?.defaultTestResult !== undefined
}

function matchesResponseStub(command: string, stub: MockResponseStub): boolean {
  if (typeof stub.command === "string") return stub.command === command
  return stub.command.test(command)
}

function getResponseStub(
  command: string,
  options: MockCommandOptions | undefined
): MockResponseStub | undefined {
  return options?.responseStubs?.find((stub) => matchesResponseStub(command, stub))
}

function findExplicitMatch(input: {
  command: string
  options?: MockCommandOptions
  responses?: MockResponses
}): Partial<ExecResult> | undefined {
  const match = input.responses?.[input.command]
  if (match) return match
  const stub = getResponseStub(input.command, input.options)
  return stub?.result
}

function getFlagLockInternalDefault(
  command: string,
  kind: "exec" | "output" | "test",
  options: MockCommandOptions | undefined
): Partial<ExecResult> | undefined {
  if (options?.allowFlagLockInternalDefaults !== true) return undefined
  // R-0000634: holder readback (via `ssh.output`) returns the deterministic
  // token so the verified-release command can be matched.
  if (isFlagLockHolderReadback(command)) return { code: 0, stdout: MOCK_FLAG_LOCK_HOLDER_TOKEN }
  if (kind !== "exec") return undefined
  if (isFlagLockReclaimProbe(command)) return { code: 1 }
  if (isFlagLockInternalSuccessCommand(command)) return { code: 0 }
  return undefined
}

function isStrictlyAllowed(input: {
  command: string
  kind: "exec" | "output" | "test"
  options?: MockCommandOptions
}): boolean {
  const allowlist = getAllowlistForKind(input.kind, input.options)
  return isAllowed(input.command, allowlist)
}

function getMockResponse(input: {
  command: string
  kind: "exec" | "output" | "test"
  options?: MockCommandOptions
  responses?: MockResponses
}): Partial<ExecResult> | undefined {
  const match = findExplicitMatch(input)
  if (match) return match

  const internal = getFlagLockInternalDefault(input.command, input.kind, input.options)
  if (internal) return internal

  const hasExplicitDefault = hasExplicitDefaultForKind(input.kind, input.options)

  const strict = input.options?.strict ?? true
  const canUseDefault = hasExplicitDefault && input.options?.allowUnstubbedDefaults === true
  if (strict && !canUseDefault && !isStrictlyAllowed(input)) {
    throw buildUnstubbedCommandError(input.kind, input.command)
  }

  return undefined
}

function buildExecResult(match?: Partial<ExecResult>): ExecResult {
  return {
    code: match?.code ?? 0,
    stderr: match?.stderr ?? "",
    stdout: match?.stdout ?? "",
  }
}

function buildCommandError(command: string, result: ExecResult): Error {
  return new Error(
    `Command failed with exit code ${String(result.code)}: ${command}\nstdout: ${result.stdout}\nstderr: ${result.stderr}`
  )
}

function rejectNonZeroExit(input: {
  command: string
  execOptions: ExecOptions | undefined
  options: MockCommandOptions | undefined
  result: ExecResult
}): void {
  const { command, execOptions, options, result } = input
  if (
    options?.rejectNonZeroExit !== false &&
    result.code !== 0 &&
    execOptions?.ignoreExitCode !== true
  ) {
    throw buildCommandError(command, result)
  }
}

type ExecRecorder = { calls: string[]; execCalls: ExecCall[] }

export function createExec(
  recorder: ExecRecorder,
  responses?: MockResponses,
  options?: MockCommandOptions
): SshConnection["exec"] {
  // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
  return async (command, execOptions) => {
    recorder.calls.push(command)
    recorder.execCalls.push({ command, options: execOptions })
    const match = getMockResponse({ command, kind: "exec", options, responses })
    if (match) {
      const result = buildExecResult(match)
      rejectNonZeroExit({ command, execOptions, options, result })
      return result
    }
    if (options?.defaultExecResult === "throw") {
      throw buildUnstubbedCommandError("exec", command)
    }
    const defaultResult = buildExecResult(options?.defaultExecResult)
    rejectNonZeroExit({ command, execOptions, options, result: defaultResult })
    return defaultResult
  }
}

export function createOutput(
  calls: string[],
  responses?: MockResponses,
  options?: MockCommandOptions
): SshConnection["output"] {
  // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
  return async (command) => {
    calls.push(command)
    const match = getMockResponse({ command, kind: "output", options, responses })
    const result = buildExecResult(match ?? { stdout: options?.defaultOutputResult })
    rejectNonZeroExit({ command, execOptions: undefined, options, result })
    return result.stdout.trim()
  }
}

export function createTest(
  calls: string[],
  responses?: MockResponses,
  options?: MockCommandOptions
): SshConnection["test"] {
  const defaultResult = options?.defaultTestResult ?? true
  const warnOnUnstubbed = options?.warnOnUnstubbedTest ?? false
  // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
  return async (command) => {
    calls.push(command)
    const match = getMockResponse({ command, kind: "test", options, responses })
    if (match) return match.code === 0
    if (warnOnUnstubbed) {
      console.warn(`createMockSsh: unstubbed test call: ${command}`)
    }
    return defaultResult
  }
}
