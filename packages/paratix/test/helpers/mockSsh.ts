import type { ExecOptions, ExecResult, SshConnection } from "../../src/types.js"

import { shellQuote } from "../../src/ssh.js"

// cspell:ignore unstubbed

const noop = async (): Promise<void> => {
  /* mock noop */
}
const noopMethod = (): void => {
  /* mock noop */
}

type MockResponses = Record<string, Partial<ExecResult>>

type MockSshOptions = {
  allowUnstubbedExec?: string[]
  allowUnstubbedOutput?: string[]
  allowUnstubbedTest?: string[]
  /**
   * Result returned by `ssh.exec()` for unstubbed commands.
   * Defaults to a successful `{ code: 0, stderr: "", stdout: "" }` for
   * backward compatibility. Set to a partial `ExecResult` (e.g.
   * `{ code: 1, stderr: "command not found" }`) to surface failures, or to
   * the literal string `"throw"` to make unstubbed exec calls reject.
   */
  defaultExecResult?: "throw" | Partial<ExecResult>
  /**
   * Result returned by `ssh.test()` for unstubbed commands.
   * Defaults to `true` for backward compatibility — tests that want to opt
   * into a stricter posture can set this to `false` so unstubbed `test`
   * calls surface as failed predicates rather than silent positives.
   */
  defaultTestResult?: boolean
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

type MockSsh = {
  addPortCalls: number[]
  calls: string[]
  execCalls: ExecCall[]
  removePortCalls: number[]
  updateHostCalls: string[]
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

function getMockResponse(input: {
  command: string
  kind: "exec" | "output" | "test"
  options?: MockSshOptions
  responses?: MockResponses
}): Partial<ExecResult> | undefined {
  const match = input.responses?.[input.command]
  if (match) return match

  const allowlist = getAllowlistForKind(input.kind, input.options)

  if (input.options?.strict && !isAllowed(input.command, allowlist)) {
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
    if (match) return buildExecResult(match)
    if (options?.defaultExecResult === "throw") {
      throw buildUnstubbedCommandError("exec", command)
    }
    return buildExecResult(options?.defaultExecResult)
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
    return getMockResponse({ command, kind: "output", options, responses })?.stdout?.trim() ?? ""
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
      // eslint-disable-next-line no-console -- Opt-in test diagnostics
      console.warn(`createMockSsh: unstubbed test call: ${command}`)
    }
    return defaultResult
  }
}

type RecordingSpies = {
  addPort: (port: number) => void
  addPortCalls: number[]
  removePort: (port: number) => void
  removePortCalls: number[]
  updateHost: (host: string) => void
  updateHostCalls: string[]
}

function createRecordingSpies(): RecordingSpies {
  const addPortCalls: number[] = []
  const removePortCalls: number[] = []
  const updateHostCalls: string[] = []
  return {
    addPort: (port) => {
      addPortCalls.push(port)
    },
    addPortCalls,
    removePort: (port) => {
      removePortCalls.push(port)
    },
    removePortCalls,
    updateHost: (host) => {
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
  const spies = createRecordingSpies()
  const exec = createExec({ calls, execCalls }, responses, options)
  const output = createOutput(calls, responses, options)
  const test = createTest(calls, responses, options)
  return {
    addPort: spies.addPort,
    addPortCalls: spies.addPortCalls,
    calls,
    disconnect: noopMethod,
    downloadFile: noop,
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
    output,
    probeSudo: noop,
    async readFile(path) {
      return this.output(`cat ${shellQuote(path)}`)
    },
    removePort: spies.removePort,
    removePortCalls: spies.removePortCalls,
    async sha256(path) {
      const exists = await this.test(`[ -f ${shellQuote(path)} ]`)
      if (!exists) return null
      return responses?.[`sha256sum ${shellQuote(path)}`]?.stdout?.split(/\s+/v)[0] ?? "abc123"
    },
    test,
    updateHost: spies.updateHost,
    updateHostCalls: spies.updateHostCalls,
    uploadFile: noop,
    writeFile: noop,
  }
}

export function createStrictMockSsh(
  responses?: MockResponses,
  options?: Omit<MockSshOptions, "strict">
): MockSsh {
  return createMockSsh(responses, { ...options, strict: true })
}
