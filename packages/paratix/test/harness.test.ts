import { describe, expect, it, vi } from "vitest"

import {
  createDockerResourceMetadata,
  ensureIntegrationRuntimeIsAvailable,
} from "./integration/harness.js"

type CommandCall = {
  arguments: string[]
  command: string
}

function commandKey(command: string, commandArguments: string[]): string {
  return [command, ...commandArguments].join(" ")
}

function createCommandRunner(responses: Partial<Record<string, Error | string>>): {
  calls: CommandCall[]
  run: ReturnType<typeof vi.fn>
} {
  const calls: CommandCall[] = []
  const run = vi.fn(async (command: string, commandArguments: string[]) => {
    calls.push({ arguments: commandArguments, command })
    const response = responses[commandKey(command, commandArguments)]
    if (response instanceof Error) throw response
    if (response == null) {
      throw new Error(`Unexpected command: ${commandKey(command, commandArguments)}`)
    }
    await Promise.resolve()
    return response
  })
  return { calls, run }
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

describe("ensureIntegrationRuntimeIsAvailable", () => {
  it("does not start Colima implicitly when it is stopped on macOS", async () => {
    const { calls, run } = createCommandRunner({
      "colima status": "Stopped",
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
      { arguments: ["colima"], command: "which" },
      { arguments: ["status"], command: "colima" },
    ])
  })

  it("starts Colima on macOS when explicitly opted in", async () => {
    const { calls, run } = createCommandRunner({
      "colima start": "",
      "colima status": "Stopped",
      "docker info": "Server Version: 1.0.0",
      "which colima": "/opt/homebrew/bin/colima",
    })

    await ensureIntegrationRuntimeIsAvailable({
      env: { PARATIX_INTEGRATION_START_COLIMA: "true" },
      platform: "darwin",
      run,
    })

    expect(calls).toStrictEqual([
      { arguments: ["colima"], command: "which" },
      { arguments: ["status"], command: "colima" },
      { arguments: ["start"], command: "colima" },
      { arguments: ["info"], command: "docker" },
    ])
  })

  it("does not start Colima implicitly when status fails on macOS", async () => {
    const { calls, run } = createCommandRunner({
      "colima status": new Error("status failed"),
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
      { arguments: ["colima"], command: "which" },
      { arguments: ["status"], command: "colima" },
    ])
  })
})
