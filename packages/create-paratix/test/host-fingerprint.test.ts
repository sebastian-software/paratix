import { describe, expect, it, vi } from "vitest"

import { readHostFingerprintViaSsh2 } from "../src/hostFingerprintBootstrap.js"
import { callHostVerifier, createFakeHostKeyClient, useFakeHostKeyClient } from "./helpers.js"

describe("readHostFingerprintViaSsh2", () => {
  it("derives the OpenSSH fingerprint from the ssh2 hostVerifier key", async () => {
    const hostKey = Buffer.from(
      "0000000b7373682d6564323535313900000020e04a2a8d2c1b47d9c6b4d114e9d2a1ea4ad8eb49c1a14851771ab0ef0457f12",
      "hex"
    )
    const fakeClient = createFakeHostKeyClient((config, client) => {
      callHostVerifier(config, hostKey)
      setImmediate(() => {
        client.handlers.error(new Error("Host denied"))
      })
    })

    await expect(
      readHostFingerprintViaSsh2("example.com", {
        clientFactory: () => useFakeHostKeyClient(fakeClient),
      })
    ).resolves.toStrictEqual({
      algorithm: "ssh-ed25519",
      fingerprint: "SHA256:MYVLAwRUnY5x4jwQ1SPUJoYXVb/fB/L3kFjCi5WxfYA",
    })

    expect(fakeClient.connect).toHaveBeenCalledWith(
      expect.objectContaining({
        host: "example.com",
        port: 22,
        readyTimeout: 10_000,
        username: "paratix-hostkey-scan",
      })
    )
  })

  it("fails clearly when ssh2 cannot obtain a host key", async () => {
    const fakeClient = createFakeHostKeyClient((_config, client) => {
      setImmediate(() => {
        client.handlers.error(new Error("connect ECONNREFUSED"))
      })
    })

    await expect(
      readHostFingerprintViaSsh2("example.com", {
        clientFactory: () => useFakeHostKeyClient(fakeClient),
      })
    ).rejects.toThrow("Failed to read the host key from example.com:22: connect ECONNREFUSED")
  })

  it("rejects with a MITM warning when the presented key uses an unknown algorithm", async () => {
    // Wire-format buffer with algorithm "ssh-bogus" (length-prefixed ASCII).
    const algoName = "ssh-bogus"
    const algoBytes = Buffer.from(algoName, "ascii")
    const lengthPrefix = Buffer.alloc(4)
    lengthPrefix.writeUInt32BE(algoBytes.length, 0)
    const hostKey = Buffer.concat([lengthPrefix, algoBytes, Buffer.from("payload")])

    const verdicts: Array<boolean | undefined> = []

    const fakeClient = createFakeHostKeyClient((config, client) => {
      verdicts.push(callHostVerifier(config, hostKey))
      setImmediate(() => {
        client.handlers.error(new Error("Host denied"))
      })
    })

    await expect(
      readHostFingerprintViaSsh2("example.com", {
        clientFactory: () => useFakeHostKeyClient(fakeClient),
      })
    ).rejects.toThrow(/unsupported SSH host key algorithm "ssh-bogus"/v)

    expect(verdicts).toStrictEqual([false])
  })

  it("rejects with a MITM warning when the presented key buffer is too short", async () => {
    const truncatedKey = Buffer.from([0, 0])

    const fakeClient = createFakeHostKeyClient((config, client) => {
      callHostVerifier(config, truncatedKey)
      setImmediate(() => {
        client.handlers.close()
      })
    })

    await expect(
      readHostFingerprintViaSsh2("example.com", {
        clientFactory: () => useFakeHostKeyClient(fakeClient),
      })
    ).rejects.toThrow(/Invalid SSH host key buffer/v)
  })

  it("settles host key verifier errors raised from an asynchronous ssh2 callback", async () => {
    // Wire-format buffer with algorithm "ssh-bogus" (length-prefixed ASCII).
    const algoName = "ssh-bogus"
    const algoBytes = Buffer.from(algoName, "ascii")
    const lengthPrefix = Buffer.alloc(4)
    lengthPrefix.writeUInt32BE(algoBytes.length, 0)
    const hostKey = Buffer.concat([lengthPrefix, algoBytes, Buffer.from("payload")])

    const verdicts: Array<boolean | undefined> = []

    const fakeClient = createFakeHostKeyClient((config, client) => {
      setImmediate(() => {
        verdicts.push(callHostVerifier(config, hostKey))
        client.handlers.error(new Error("Host denied"))
      })
    })

    await expect(
      readHostFingerprintViaSsh2("example.com", {
        clientFactory: () => useFakeHostKeyClient(fakeClient),
      })
    ).rejects.toThrow(/unsupported SSH host key algorithm "ssh-bogus"/v)

    expect(verdicts).toStrictEqual([false])
  })

  // R-0000127: ssh2 cannot detect a TCP half-open state; if neither close
  // nor error fires, the Promise must still settle through the watchdog.
  it("rejects through the watchdog when ssh2 never fires close or error", async () => {
    vi.useFakeTimers()

    const fakeClient = createFakeHostKeyClient(() => {
      // Intentionally do not invoke any handler — simulate a half-open
      // socket where neither error nor close ever fire.
    })

    try {
      const promise = readHostFingerprintViaSsh2("example.com", {
        clientFactory: () => useFakeHostKeyClient(fakeClient),
        readyTimeoutMs: 5000,
      })

      // Attach a no-op rejection handler before advancing timers so the
      // watchdog can settle the promise without an unhandled-rejection
      // warning from Node, then advance timers and assert.
      promise.catch(() => {
        // Swallow the rejection until the assertion below observes it.
      })
      // Watchdog is armed at readyTimeoutMs * 2 = 10_000ms.
      await vi.advanceTimersByTimeAsync(10_001)
      await expect(promise).rejects.toThrow(/host key scan timed out after 10000ms/v)

      expect(fakeClient.removeAllListeners).toHaveBeenCalled()
    } finally {
      vi.useRealTimers()
    }
  })

  // R-0000127: when the close handler resolves first, the watchdog must be
  // cleared so it cannot keep the event loop alive or fire spuriously.
  it("clears the watchdog on a successful resolution", async () => {
    const hostKey = Buffer.from(
      "0000000b7373682d6564323535313900000020e04a2a8d2c1b47d9c6b4d114e9d2a1ea4ad8eb49c1a14851771ab0ef0457f12",
      "hex"
    )

    const clearTimeoutSpy = vi.spyOn(globalThis, "clearTimeout")

    try {
      const fakeClient = createFakeHostKeyClient((config, client) => {
        callHostVerifier(config, hostKey)
        setImmediate(() => {
          client.handlers.error(new Error("Host denied"))
        })
      })

      await expect(
        readHostFingerprintViaSsh2("example.com", {
          clientFactory: () => useFakeHostKeyClient(fakeClient),
        })
      ).resolves.toMatchObject({ algorithm: "ssh-ed25519" })

      expect(clearTimeoutSpy).toHaveBeenCalled()
    } finally {
      clearTimeoutSpy.mockRestore()
    }
  })
})
