import type * as FsPromises from "node:fs/promises"

import { execFile } from "node:child_process"
import { writeFileSync } from "node:fs"
import { access, rm } from "node:fs/promises"
import { resolve } from "node:path"
import { afterEach, describe, expect, it, vi } from "vitest"

import {
  createDockerResourceMetadata,
  createIntegrationEnvironment,
  ensureIntegrationRuntimeIsAvailable,
  restoreHomeEnvironmentVariable,
} from "./integration/harness.js"

type CommandRunner = (
  command: string,
  commandArguments: string[],
  options?: { cwd?: string; timeoutMs?: number }
) => Promise<string>

vi.mock("node:child_process", () => ({
  execFile: vi.fn(),
}))

vi.mock("node:fs/promises", async () => {
  const actual = await vi.importActual<typeof FsPromises>("node:fs/promises")
  return {
    ...actual,
    rm: vi.fn(actual.rm),
  }
})

type CommandCall = {
  arguments: string[]
  command: string
}

function commandKey(command: string, commandArguments: string[]): string {
  return [command, ...commandArguments].join(" ")
}

function createCommandRunner(
  responses: Partial<Record<string, Array<Error | string> | Error | string>>
): {
  calls: CommandCall[]
  run: CommandRunner
} {
  const calls: CommandCall[] = []
  const run = vi.fn(async (command: string, commandArguments: string[]) => {
    calls.push({ arguments: commandArguments, command })
    const response = responses[commandKey(command, commandArguments)]
    if (Array.isArray(response)) {
      const nextResponse = response.shift()
      if (nextResponse instanceof Error) throw nextResponse
      if (nextResponse == null) {
        throw new Error(`Unexpected command: ${commandKey(command, commandArguments)}`)
      }
      await Promise.resolve()
      return nextResponse
    }
    if (response instanceof Error) throw response
    if (response == null) {
      throw new Error(`Unexpected command: ${commandKey(command, commandArguments)}`)
    }
    await Promise.resolve()
    return response
  })
  return { calls, run }
}

const mockExecFile = vi.mocked(execFile)
const mockRm = vi.mocked(rm)

function mockIntegrationBuildFailure(
  commands: CommandCall[],
  output: { stderr?: string; stdout?: string } = {}
): void {
  mockExecFile.mockImplementation((...callArguments: unknown[]) => {
    const command = callArguments[0] as string
    const commandArguments = callArguments[1] as string[]
    const callback = callArguments.at(-1) as (
      error: Error | null,
      stdout: string,
      stderr: string
    ) => void
    commands.push({ arguments: commandArguments, command })
    if (command === "colima" && commandArguments[0] === "status") {
      callback(null, "Running", "")
      return undefined as never
    }
    if (command === "ssh-keygen") {
      const privateKeyPath = commandArguments.at(commandArguments.indexOf("-f") + 1)
      if (privateKeyPath == null) throw new Error("ssh-keygen test call is missing -f")
      writeFileSync(privateKeyPath, "test private key")
      writeFileSync(`${privateKeyPath}.pub`, "ssh-ed25519 test-public-key paratix-integration")
      callback(null, "ok", "")
      return undefined as never
    }
    if (command === "docker" && commandArguments[0] === "build") {
      callback(
        new Error("build failed"),
        output.stdout ?? "",
        output.stderr ?? "docker build failed"
      )
      return undefined as never
    }
    callback(null, "ok", "")
    return undefined as never
  })
}

describe("createDockerResourceMetadata", () => {
  it("uses a generated UUID suffix for collision-resistant Docker names", () => {
    const first = createDockerResourceMetadata()
    const second = createDockerResourceMetadata()
    const firstSuffix = first.containerName.slice("paratix-integration-".length)

    expect(first.containerName).toBe(`paratix-integration-${firstSuffix}`)
    expect(firstSuffix).toHaveLength("11111111-2222-4333-8444-555555555555".length)
    expect(firstSuffix.split("-").map((part) => part.length)).toStrictEqual([8, 4, 4, 4, 12])
    for (const character of firstSuffix) {
      expect("0123456789abcdef-").toContain(character)
    }
    expect(first.dockerImageTag).toBe(
      first.containerName.replace("paratix-integration-", "paratix-integration-sshd:")
    )
    expect(first.containerName).not.toBe(second.containerName)
    expect(first.dockerImageTag).not.toBe(second.dockerImageTag)
  })

  it("sets labels that identify the generated Docker resources", () => {
    const resourceId = "11111111-2222-4333-8444-555555555555"

    expect(createDockerResourceMetadata(resourceId)).toStrictEqual({
      containerName: `paratix-integration-${resourceId}`,
      dockerImageTag: `paratix-integration-sshd:${resourceId}`,
      labels: [
        "com.sebastian-software.paratix.integration.managed=true",
        `com.sebastian-software.paratix.integration.id=${resourceId}`,
      ],
    })
  })
})

describe("createIntegrationEnvironment", () => {
  afterEach(() => {
    vi.clearAllMocks()
  })

  it("removes the temporary workspace home when the Docker build fails", async () => {
    const commands: CommandCall[] = []
    mockIntegrationBuildFailure(commands)

    await expect(createIntegrationEnvironment(resolve(import.meta.dirname, ".."))).rejects.toThrow(
      "docker build failed"
    )

    const workspaceHome = mockRm.mock.calls
      .map(([path]) => String(path))
      .find((path) => path.includes("paratix-integration-home-"))
    expect(workspaceHome).toBeDefined()
    await expect(access(workspaceHome!)).rejects.toThrow("ENOENT")
    expect(
      commands.map(({ arguments: commandArguments, command }) =>
        commandKey(command, commandArguments)
      )
    ).toStrictEqual(
      expect.arrayContaining([
        "docker info",
        expect.stringMatching(
          /^ssh-keygen -t ed25519 -N {2}-f .*client_ed25519 -C paratix-integration$/v
        ),
        expect.stringMatching(
          /^docker build .* --build-arg CLIENT_PUBLIC_KEY=ssh-ed25519 test-public-key paratix-integration /v
        ),
        expect.stringMatching(/^docker build /v),
        expect.stringMatching(/^docker rm -f paratix-integration-/v),
        expect.stringMatching(/^docker image rm -f paratix-integration-sshd:/v),
      ])
    )
  })

  it("includes stdout and stderr tails when a setup command fails", async () => {
    const commands: CommandCall[] = []
    mockIntegrationBuildFailure(commands, {
      stderr: "stderr diagnostic",
      stdout: "stdout diagnostic",
    })

    await expect(createIntegrationEnvironment(resolve(import.meta.dirname, ".."))).rejects.toThrow(
      "stdout:\nstdout diagnostic\nstderr:\nstderr diagnostic"
    )
  })

  it("bounds command failure stdout and stderr details", async () => {
    const commands: CommandCall[] = []
    const longStdout = `stdout-start\n${"o".repeat(9000)}stdout-end`
    const longStderr = `stderr-start\n${"e".repeat(9000)}stderr-end`
    mockIntegrationBuildFailure(commands, {
      stderr: longStderr,
      stdout: longStdout,
    })

    let caughtError: unknown
    try {
      await createIntegrationEnvironment(resolve(import.meta.dirname, ".."))
    } catch (error) {
      caughtError = error
    }

    expect(caughtError).toBeInstanceOf(Error)
    const message = (caughtError as Error).message
    expect(message).toContain("stdout-end")
    expect(message).toContain("stderr-end")
    expect(message).not.toContain("stdout-start")
    expect(message).not.toContain("stderr-start")
    expect(message.length).toBeLessThan(longStdout.length + longStderr.length)
  })
})

describe("restoreHomeEnvironmentVariable", () => {
  it("restores the previous environment variable value", () => {
    const previousHome = process.env.HOME

    try {
      process.env.HOME = "/tmp/test-home"

      restoreHomeEnvironmentVariable("/Users/example")

      expect(process.env.HOME).toBe("/Users/example")
    } finally {
      restoreHomeEnvironmentVariable(previousHome)
    }
  })

  it("deletes the environment variable when it was previously unset", () => {
    const previousHome = process.env.HOME

    try {
      process.env.HOME = "/tmp/test-home"

      restoreHomeEnvironmentVariable(undefined)

      expect(Object.hasOwn(process.env, "HOME")).toBe(false)
    } finally {
      restoreHomeEnvironmentVariable(previousHome)
    }
  })
})

describe("ensureIntegrationRuntimeIsAvailable", () => {
  afterEach(() => {
    vi.clearAllMocks()
  })

  it("uses reachable Docker on macOS without checking Colima", async () => {
    const { calls, run } = createCommandRunner({
      "docker info": "Server Version: 1.0.0",
    })

    await ensureIntegrationRuntimeIsAvailable({
      env: {},
      platform: "darwin",
      run,
    })

    expect(calls).toStrictEqual([{ arguments: ["info"], command: "docker" }])
  })

  it("does not start Colima implicitly when it is stopped on macOS", async () => {
    const { calls, run } = createCommandRunner({
      "colima status": "Stopped",
      "docker info": new Error("docker unavailable"),
      "which colima": "/opt/homebrew/bin/colima",
    })

    await expect(
      ensureIntegrationRuntimeIsAvailable({
        env: {},
        platform: "darwin",
        run,
      })
    ).rejects.toThrow("PARATIX_INTEGRATION_START_COLIMA=true")

    expect(calls).toStrictEqual([
      { arguments: ["info"], command: "docker" },
      { arguments: ["colima"], command: "which" },
      { arguments: ["status"], command: "colima" },
    ])
  })

  it("does not treat not running Colima status as running on macOS", async () => {
    const { calls, run } = createCommandRunner({
      "colima status": "not running",
      "docker info": new Error("docker unavailable"),
      "which colima": "/opt/homebrew/bin/colima",
    })

    await expect(
      ensureIntegrationRuntimeIsAvailable({
        env: {},
        platform: "darwin",
        run,
      })
    ).rejects.toThrow("PARATIX_INTEGRATION_START_COLIMA=true")

    expect(calls).toStrictEqual([
      { arguments: ["info"], command: "docker" },
      { arguments: ["colima"], command: "which" },
      { arguments: ["status"], command: "colima" },
    ])
  })

  it("starts Colima on macOS when explicitly opted in", async () => {
    const { calls, run } = createCommandRunner({
      "colima start": "",
      "colima status": "Stopped",
      "docker info": [new Error("docker unavailable"), "Server Version: 1.0.0"],
      "which colima": "/opt/homebrew/bin/colima",
    })

    await ensureIntegrationRuntimeIsAvailable({
      env: { PARATIX_INTEGRATION_START_COLIMA: "true" },
      platform: "darwin",
      run,
    })

    expect(calls).toStrictEqual([
      { arguments: ["info"], command: "docker" },
      { arguments: ["colima"], command: "which" },
      { arguments: ["status"], command: "colima" },
      { arguments: ["start"], command: "colima" },
      { arguments: ["info"], command: "docker" },
    ])
  })

  it("starts Colima when not running on macOS and explicitly opted in", async () => {
    const { calls, run } = createCommandRunner({
      "colima start": "",
      "colima status": "not running",
      "docker info": [new Error("docker unavailable"), "Server Version: 1.0.0"],
      "which colima": "/opt/homebrew/bin/colima",
    })

    await ensureIntegrationRuntimeIsAvailable({
      env: { PARATIX_INTEGRATION_START_COLIMA: "true" },
      platform: "darwin",
      run,
    })

    expect(calls).toStrictEqual([
      { arguments: ["info"], command: "docker" },
      { arguments: ["colima"], command: "which" },
      { arguments: ["status"], command: "colima" },
      { arguments: ["start"], command: "colima" },
      { arguments: ["info"], command: "docker" },
    ])
  })

  it("does not start Colima implicitly when status fails on macOS", async () => {
    const { calls, run } = createCommandRunner({
      "colima status": new Error("status failed"),
      "docker info": new Error("docker unavailable"),
      "which colima": "/opt/homebrew/bin/colima",
    })

    await expect(
      ensureIntegrationRuntimeIsAvailable({
        env: {},
        platform: "darwin",
        run,
      })
    ).rejects.toThrow("PARATIX_INTEGRATION_START_COLIMA=true")

    expect(calls).toStrictEqual([
      { arguments: ["info"], command: "docker" },
      { arguments: ["colima"], command: "which" },
      { arguments: ["status"], command: "colima" },
    ])
  })
})
