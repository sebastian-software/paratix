import { describe, expect, it, vi } from "vitest"

import { makeMockSshClass } from "./runnerMocks.js"

describe("makeMockSshClass", () => {
  it("rejects unstubbed probeSudo calls", async () => {
    const MockSshConnection = makeMockSshClass([])
    const ssh = new MockSshConnection("1.2.3.4", {}) as { probeSudo: () => Promise<void> }

    await expect(ssh.probeSudo()).rejects.toThrow(
      "makeMockSshClass: unstubbed SSH method call: probeSudo"
    )
  })

  it("allows probeSudo when explicitly overridden", async () => {
    const probeSudo = vi.fn().mockResolvedValue(undefined)
    const MockSshConnection = makeMockSshClass([], { probeSudo })
    const ssh = new MockSshConnection("1.2.3.4", {}) as { probeSudo: () => Promise<void> }

    await expect(ssh.probeSudo()).resolves.toBeUndefined()

    expect(probeSudo).toHaveBeenCalledOnce()
  })
})
