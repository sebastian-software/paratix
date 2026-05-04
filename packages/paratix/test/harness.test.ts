import { describe, expect, it, vi } from "vitest"

import { ensureIntegrationRuntimeIsAvailable } from "./integration/harness.js"

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
