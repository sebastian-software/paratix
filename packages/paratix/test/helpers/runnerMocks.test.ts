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
    const MockSshConnection = makeMockSshClass([], { lifecycle: "permissive" })
    const ssh = new MockSshConnection("203.0.113.10", {}) as {
      getConnectionInfo: () => { host: string }
      updateHost: (host: string) => void
    }

    ssh.updateHost("203.0.113.42")

    expect(ssh.getConnectionInfo().host).toBe("203.0.113.42")
  })

  it.each(["addPort", "disconnect", "removePort", "updateHost"] as const)(
    "throws on unstubbed %s calls",
    (methodName) => {
      const MockSshConnection = makeMockSshClass([])
      const ssh = new MockSshConnection("1.2.3.4", {}) as Record<string, (value?: unknown) => void>

      expect(() => {
        ssh[methodName](2222)
      }).toThrow(`makeMockSshClass: unstubbed SSH method call: ${methodName}`)
    }
  )

  it.each(["connect", "reconnect"] as const)("rejects unstubbed %s calls", async (methodName) => {
    const MockSshConnection = makeMockSshClass([])
    const ssh = new MockSshConnection("1.2.3.4", {}) as Record<string, () => Promise<void>>

    await expect(ssh[methodName]()).rejects.toThrow(
      `makeMockSshClass: unstubbed SSH method call: ${methodName}`
    )
  })

  it("allows lifecycle calls when explicitly configured as permissive", async () => {
    const MockSshConnection = makeMockSshClass([], { lifecycle: "permissive" })
    const ssh = new MockSshConnection("1.2.3.4", {}) as {
      addPort: (port: number) => boolean
      connect: () => Promise<void>
      disconnect: () => void
      reconnect: () => Promise<void>
      removePort: (port: number) => void
      updateHost: (host: string) => void
    }

    expect(ssh.addPort(2222)).toBe(true)
    await expect(ssh.connect()).resolves.toBeNull()
    ssh.disconnect()
    await expect(ssh.reconnect()).resolves.toBeNull()
    ssh.removePort(2222)
    ssh.updateHost("203.0.113.42")
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
