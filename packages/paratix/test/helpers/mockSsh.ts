import type { ExecOptions, ExecResult, SshConnection } from "../../src/types.js"

import { shellQuote } from "../../src/ssh.js"
import { isFlagLockInternalSuccessCommand, isFlagLockReclaimProbe } from "./mockSshFlagLock.js"
import {
  createSideEffectRecorder,
  type DownloadFileCall,
  type SideEffectOptions,
  type UploadFileCall,
  type WriteFileCall,
} from "./mockSshSideEffects.js"

type MockResponses = Record<string, Partial<ExecResult>>

type MockResponseStub = {
  command: RegExp | string
  result: Partial<ExecResult>
}

type MockSshOptions = {
  allowUnstubbedExec?: string[]
  allowUnstubbedOutput?: string[]
  allowUnstubbedTest?: string[]
  /**
   * Result returned by `ssh.exec()` for unstubbed commands.
   * By default, unstubbed calls reject. Set this to a partial `ExecResult`
   * when a test intentionally does not care about a specific command.
   */
  defaultExecResult?: "throw" | Partial<ExecResult>
  /**
   * Result returned by `ssh.output()` for unstubbed commands.
   * By default, unstubbed calls reject. Set this when a test intentionally
   * does not care about a specific output command.
   */
  defaultOutputResult?: string
  /**
   * Result returned by `ssh.test()` for unstubbed commands.
   * By default, unstubbed calls reject. Set this when a test intentionally
   * treats unspecified predicates as true or false.
   */
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
  /**
   * When `true`, log a `console.warn` for every unstubbed `ssh.test()` call so
   * test authors can audit silent permissive matches. Off by default to keep
   * existing test runs quiet.
   */
  warnOnUnstubbedTest?: boolean
} & SideEffectOptions

/** Recorded `ssh.exec` invocation: the command string plus the options it received. */
export type ExecCall = { command: string; options: ExecOptions | undefined }

type MockSsh = {
  addPortCalls: number[]
  calls: string[]
  disconnectCalls: Array<Record<never, never>>
  downloadFileCalls: DownloadFileCall[]
  execCalls: ExecCall[]
  probeSudoCalls: Array<Record<never, never>>
  removePortCalls: number[]
  updateHostCalls: string[]
  uploadFileCalls: UploadFileCall[]
  writeFileCalls: WriteFileCall[]
} & SshConnection

function isAllowed(command: string, allowed?: string[]): boolean {
  return allowed?.includes(command) ?? false
}

function buildUnstubbedCommandError(kind: "exec" | "output" | "test", command: string): Error {
  return new Error(`createMockSsh: unstubbed ${kind} call: ${command}`)
}

function getAllowlistForKind(
  kind: "exec" | "output" | "test",
  options: MockSshOptions | undefined
): string[] | undefined {
  if (kind === "exec") return options?.allowUnstubbedExec
  if (kind === "output") return options?.allowUnstubbedOutput
  return options?.allowUnstubbedTest
}

function hasExplicitDefaultForKind(
  kind: "exec" | "output" | "test",
  options: MockSshOptions | undefined
): boolean {
  switch (kind) {
    case "exec": {
      return options?.defaultExecResult !== undefined
    }
    case "output": {
      return options?.defaultOutputResult !== undefined
    }
    case "test": {
      return options?.defaultTestResult !== undefined
    }
  }
}

function matchesResponseStub(command: string, stub: MockResponseStub): boolean {
  if (typeof stub.command === "string") return stub.command === command
  return stub.command.test(command)
}

function getResponseStub(
  command: string,
  options: MockSshOptions | undefined
): MockResponseStub | undefined {
  return options?.responseStubs?.find((stub) => matchesResponseStub(command, stub))
}

function findExplicitMatch(input: {
  command: string
  options?: MockSshOptions
  responses?: MockResponses
}): Partial<ExecResult> | undefined {
  const match = input.responses?.[input.command]
  if (match) return match
  const stub = getResponseStub(input.command, input.options)
  return stub?.result
}

function getFlagLockInternalDefault(
  command: string,
  kind: "exec" | "output" | "test"
): Partial<ExecResult> | undefined {
  if (kind !== "exec") return undefined
  if (isFlagLockReclaimProbe(command)) {
    // Default the reclaim probe to "no stale lock" so untouched tests
    // do not silently change behaviour.
    return { code: 1 }
  }
  return undefined
}

function isStrictlyAllowed(input: {
  command: string
  kind: "exec" | "output" | "test"
  options?: MockSshOptions
}): boolean {
  const allowlist = getAllowlistForKind(input.kind, input.options)
  if (isAllowed(input.command, allowlist)) return true
  if (input.kind === "exec" && isFlagLockInternalSuccessCommand(input.command)) return true
  return false
}

function getMockResponse(input: {
  command: string
  kind: "exec" | "output" | "test"
  options?: MockSshOptions
  responses?: MockResponses
}): Partial<ExecResult> | undefined {
  const match = findExplicitMatch(input)
  if (match) return match

  const hasExplicitDefault = hasExplicitDefaultForKind(input.kind, input.options)
  if (!hasExplicitDefault) {
    const internal = getFlagLockInternalDefault(input.command, input.kind)
    if (internal) return internal
  }

  const strict = input.options?.strict ?? true
  if (strict && !hasExplicitDefault && !isStrictlyAllowed(input)) {
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
  options: MockSshOptions | undefined
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

function createExec(
  recorder: ExecRecorder,
  responses?: MockResponses,
  options?: MockSshOptions
): MockSsh["exec"] {
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

function createOutput(
  calls: string[],
  responses?: MockResponses,
  options?: MockSshOptions
): MockSsh["output"] {
  // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
  return async (command) => {
    calls.push(command)
    const match = getMockResponse({ command, kind: "output", options, responses })
    const result = buildExecResult(match ?? { stdout: options?.defaultOutputResult })
    rejectNonZeroExit({ command, execOptions: undefined, options, result })
    return result.stdout.trim()
  }
}

function createTest(
  calls: string[],
  responses?: MockResponses,
  options?: MockSshOptions
): MockSsh["test"] {
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

type RecordingSpies = Pick<
  MockSsh,
  "addPort" | "addPortCalls" | "removePort" | "removePortCalls" | "updateHost" | "updateHostCalls"
>

function createRecordingSpies(): RecordingSpies {
  const addPortCalls: number[] = []
  const removePortCalls: number[] = []
  const updateHostCalls: string[] = []
  return {
    addPort(port) {
      addPortCalls.push(port)
      return true
    },
    addPortCalls,
    removePort(port) {
      removePortCalls.push(port)
    },
    removePortCalls,
    updateHost(host) {
      updateHostCalls.push(host)
    },
    updateHostCalls,
  }
}

function getMockConnectionInfo(): ReturnType<SshConnection["getConnectionInfo"]> {
  return {
    authMethod: "privateKey",
    host: "1.2.3.4",
    port: 22,
    privateKeyPath: "~/.ssh/id",
    user: "root",
  }
}

export function createMockSsh(responses?: MockResponses, options?: MockSshOptions): MockSsh {
  const calls: string[] = []
  const execCalls: ExecCall[] = []
  const exec = createExec({ calls, execCalls }, responses, options)
  const spies = createRecordingSpies()
  const sideEffects = createSideEffectRecorder(options)
  return {
    addPort: spies.addPort,
    addPortCalls: spies.addPortCalls,
    calls,
    disconnect: sideEffects.disconnect,
    disconnectCalls: sideEffects.disconnectCalls,
    downloadFile: sideEffects.downloadFile,
    downloadFileCalls: sideEffects.downloadFileCalls,
    exec,
    execCalls,
    async exists(path) {
      return this.test(`[ -e ${shellQuote(path)} ]`)
    },
    getConnectionInfo: getMockConnectionInfo,
    async lines(command) {
      const out = await this.output(command)
      return out.length > 0 ? out.split("\n") : []
    },
    output: createOutput(calls, responses, options),
    probeSudo: sideEffects.probeSudo,
    probeSudoCalls: sideEffects.probeSudoCalls,
    async readFile(path) {
      const result = await exec(`cat ${shellQuote(path)}`, { silent: true })
      return result.stdout
    },
    removePort: spies.removePort,
    removePortCalls: spies.removePortCalls,
    async sha256(path) {
      const exists = await this.test(`[ -f ${shellQuote(path)} ]`)
      if (!exists) return null
      const command = `sha256sum ${shellQuote(path)}`
      const output = await this.output(command)
      return output.split(/\s+/v)[0] ?? null
    },
    test: createTest(calls, responses, options),
    updateHost: spies.updateHost,
    updateHostCalls: spies.updateHostCalls,
    uploadFile: sideEffects.uploadFile,
    uploadFileCalls: sideEffects.uploadFileCalls,
    writeFile: sideEffects.writeFile,
    writeFileCalls: sideEffects.writeFileCalls,
  }
}

export function createStrictMockSsh(
  responses?: MockResponses,
  options?: Omit<MockSshOptions, "strict">
): MockSsh {
  return createMockSsh(responses, { ...options, strict: true })
}
