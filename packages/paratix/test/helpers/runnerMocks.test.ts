import { describe, expect, it, vi } from "vitest"

import { makeMockSshClass } from "./runnerMocks.js"

describe("makeMockSshClass", () => {
  it("reports the constructor host in connection info", () => {
    const MockSshConnection = makeMockSshClass([])
    const ssh = new MockSshConnection("203.0.113.10", {}) as {
      getConnectionInfo: () => { host: string }
    }

    expect(ssh.getConnectionInfo().host).toBe("203.0.113.10")
  })

  it("updates the reported host when updateHost is not overridden", () => {
    const MockSshConnection = makeMockSshClass([])
    const ssh = new MockSshConnection("203.0.113.10", {}) as {
      getConnectionInfo: () => { host: string }
      updateHost: (host: string) => void
    }

    ssh.updateHost("203.0.113.42")

    expect(ssh.getConnectionInfo().host).toBe("203.0.113.42")
  })

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
