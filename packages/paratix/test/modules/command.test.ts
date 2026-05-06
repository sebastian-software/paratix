import { describe, expect, it } from "vitest"

import type { ExecOptions } from "../../src/types.js"

import { command } from "../../src/modules/command.js"
import { CommandError } from "../../src/sshHelpers.js"
import { createStrictMockSsh, type ExecCall } from "../helpers/mockSsh.js"

const emptyEnv = {}

type MockSshWithOptions = {
  exec: (
    command: string,
    options?: ExecOptions
  ) => Promise<{ code: number; stderr: string; stdout: string }>
  execCalls: ExecCall[]
} & ReturnType<typeof createStrictMockSsh>

function createMockSshWithOptions(
  responses?: Record<string, { code?: number; stderr?: string; stdout?: string }>
): MockSshWithOptions {
  const base = createStrictMockSsh(responses)
  const execCalls: ExecCall[] = []
  return {
    ...base,
    async exec(remoteCommand: string, options?: ExecOptions) {
      execCalls.push({ command: remoteCommand, options })
      return base.exec(remoteCommand, options)
    },
    execCalls,
  }
}

// ---------------------------------------------------------------------------
// apply — null ssh
// ---------------------------------------------------------------------------

describe("command.shell — apply with null ssh", () => {
  it("returns failed when ssh is null", async () => {
    const mod = command.shell("echo hello")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

// ---------------------------------------------------------------------------
// apply — successful command
// ---------------------------------------------------------------------------

describe("command.shell — apply with exit code 0", () => {
  it("returns changed when command exits with code 0", async () => {
    const mockSsh = createStrictMockSsh({ "echo hello": { code: 0 } })
    const mod = command.shell("echo hello")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("returns ok without executing the command when check already passes", async () => {
    const mockSsh = createMockSshWithOptions({ "which tool": { code: 0 } })
    const mod = command.shell("install-tool", { check: "which tool" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("ok")
    expect(mockSsh.execCalls).toStrictEqual([
      {
        command: "which tool",
        options: { ignoreExitCode: true, secrets: [], silent: true },
      },
    ])
  })

  it("executes the command when check does not pass", async () => {
    const mockSsh = createMockSshWithOptions({
      "install-tool": { code: 0 },
      "which tool": { code: 1 },
    })
    const mod = command.shell("install-tool", { check: "which tool" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.execCalls).toStrictEqual([
      {
        command: "which tool",
        options: { ignoreExitCode: true, secrets: [], silent: true },
      },
      {
        command: "install-tool",
        options: { ignoreExitCode: true, secrets: [], silent: true },
      },
    ])
  })

  it("passes secrets to the apply guard check", async () => {
    const secret = "guard-secret-token"
    const mockSsh = createMockSshWithOptions({ [`test -f /tmp/${secret}`]: { code: 0 } })
    const mod = command.shell("install-tool", {
      check: `test -f /tmp/${secret}`,
      secrets: [secret],
    })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("ok")
    expect(mockSsh.execCalls).toStrictEqual([
      {
        command: `test -f /tmp/${secret}`,
        options: { ignoreExitCode: true, secrets: [secret], silent: true },
      },
    ])
  })
})

// ---------------------------------------------------------------------------
// apply — failed command
// ---------------------------------------------------------------------------

describe("command.shell — apply with non-zero exit code", () => {
  it("returns failed when command exits with non-zero code", async () => {
    const mockSsh = createStrictMockSsh({ "exit 1": { code: 1 } })
    const mod = command.shell("exit 1")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(CommandError)
  })

  it("returns a centralized CommandError payload when command exits non-zero", async () => {
    const mockSsh = createStrictMockSsh({
      "exit 1": { code: 1, stderr: "some error", stdout: "some output" },
    })
    const mod = command.shell("exit 1")
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.error).toBeInstanceOf(CommandError)
    expect(result.error?.message).toContain("[command.shell] command failed (exit code 1)")
    expect(result.error).toMatchObject({
      fullStderr: "some error",
      fullStdout: "some output",
    })
  })

  it("passes secrets to ssh.exec and masks leaked stdout/stderr in the error payload", async () => {
    const secret = "super-secret-token"
    const mockSsh = createMockSshWithOptions({
      [`deploy --token ${secret}`]: {
        code: 1,
        stderr: `stderr leaked ${secret}`,
        stdout: `stdout leaked ${secret}`,
      },
    })
    const mod = command.shell(`deploy --token ${secret}`, { secrets: [secret] })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(mockSsh.execCalls).toHaveLength(1)
    expect(mockSsh.execCalls[0].options?.secrets).toStrictEqual([secret])
    expect(result.error).toBeInstanceOf(CommandError)
    expect(result.error).toMatchObject({
      fullStderr: "stderr leaked [REDACTED]",
      fullStdout: "stdout leaked [REDACTED]",
    })
  })
})

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

describe("command.shell — check", () => {
  it("returns needs-apply when no check option is provided", async () => {
    const mockSsh = createStrictMockSsh()
    const mod = command.shell("echo hello")
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when ssh is null", async () => {
    const mod = command.shell("echo hello", { check: "which tool" })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when check command exits with code 0", async () => {
    const mockSsh = createMockSshWithOptions({ "which tool": { code: 0 } })
    const mod = command.shell("install-tool", { check: "which tool" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
    expect(mockSsh.execCalls).toStrictEqual([
      {
        command: "which tool",
        options: { ignoreExitCode: true, secrets: [], silent: true },
      },
    ])
  })

  it("returns needs-apply when check command exits with non-zero code", async () => {
    const mockSsh = createMockSshWithOptions({ "which tool": { code: 1 } })
    const mod = command.shell("install-tool", { check: "which tool" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.execCalls).toStrictEqual([
      {
        command: "which tool",
        options: { ignoreExitCode: true, secrets: [], silent: true },
      },
    ])
  })

  it("passes secrets to the standalone check command", async () => {
    const secret = "check-secret-token"
    const mockSsh = createMockSshWithOptions({ [`test -f /tmp/${secret}`]: { code: 0 } })
    const mod = command.shell("install-tool", {
      check: `test -f /tmp/${secret}`,
      secrets: [secret],
    })
    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
    expect(mockSsh.execCalls).toStrictEqual([
      {
        command: `test -f /tmp/${secret}`,
        options: { ignoreExitCode: true, secrets: [secret], silent: true },
      },
    ])
  })
})

// ---------------------------------------------------------------------------
// name
// ---------------------------------------------------------------------------

describe("command.shell — name", () => {
  it("uses custom name when provided", () => {
    const mod = command.shell("echo hello", { name: "greet" })
    expect(mod.name).toBe("greet")
  })

  it("uses a generic default name instead of the raw command", () => {
    const mod = command.shell("echo hello")
    expect(mod.name).toBe("command.shell")
  })

  it("does not expose secrets from the command line in the default name", () => {
    const mod = command.shell("deploy --token super-secret-token")
    expect(mod.name).toBe("command.shell")
    expect(mod.name).not.toContain("super-secret-token")
  })
})
