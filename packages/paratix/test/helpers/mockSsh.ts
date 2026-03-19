import type { ExecResult, SshConnection } from "../../src/types.js"

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
  strict?: boolean
}

type MockSsh = { calls: string[] } & SshConnection

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

function createExec(
  calls: string[],
  responses?: MockResponses,
  options?: MockSshOptions
): MockSsh["exec"] {
  // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
  return async (command, _options) => {
    calls.push(command)
    return buildExecResult(getMockResponse({ command, kind: "exec", options, responses }))
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
  // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
  return async (command) => {
    calls.push(command)
    const match = getMockResponse({ command, kind: "test", options, responses })
    return match ? match.code === 0 : true
  }
}

export function createMockSsh(responses?: MockResponses, options?: MockSshOptions): MockSsh {
  const calls: string[] = []
  const exec = createExec(calls, responses, options)
  const output = createOutput(calls, responses, options)
  const test = createTest(calls, responses, options)
  return {
    addPort: noopMethod,
    calls,
    disconnect: noopMethod,
    downloadFile: noop,
    exec,
    async exists(path) {
      return this.test(`[ -e ${shellQuote(path)} ]`)
    },
    getConnectionInfo() {
      return { host: "1.2.3.4", port: 22, privateKeyPath: "~/.ssh/id", user: "root" }
    },
    async lines(command) {
      const out = await this.output(command)
      return out.length > 0 ? out.split("\n") : []
    },
    output,
    probeSudo: noop,
    async readFile(path) {
      return this.output(`cat ${shellQuote(path)}`)
    },
    removePort: noopMethod,
    async sha256(path) {
      const exists = await this.test(`[ -f ${shellQuote(path)} ]`)
      if (!exists) return null
      return responses?.[`sha256sum ${shellQuote(path)}`]?.stdout?.split(/\s+/v)[0] ?? "abc123"
    },
    test,
    updateHost: noopMethod,
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
