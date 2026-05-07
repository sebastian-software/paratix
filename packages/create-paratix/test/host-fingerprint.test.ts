import { createHash } from "node:crypto"
import { describe, expect, it, vi } from "vitest"

import { readHostFingerprintViaSsh2 } from "../src/hostFingerprintBootstrap.js"
import {
  buildEcdsaHostKeyBuffer,
  buildEcdsaPointFromGeneratedKey,
  buildEd25519HostKeyBuffer,
  callHostVerifier,
  createFakeHostKeyClient,
  createWireString,
  type EcdsaHostKeyFixtureSpec,
  useFakeHostKeyClient,
} from "./helpers.js"

const ED25519_PUBLIC_KEY_BYTE_LENGTH = 32
const NISTP256_UNCOMPRESSED_POINT_BYTE_LENGTH = 65
const NISTP384_UNCOMPRESSED_POINT_BYTE_LENGTH = 97
const NISTP521_UNCOMPRESSED_POINT_BYTE_LENGTH = 133
const UNCOMPRESSED_EC_POINT_PREFIX = 0x04

const ECDSA_FIXTURE_SPECS: readonly EcdsaHostKeyFixtureSpec[] = [
  {
    algorithm: "ecdsa-sha2-nistp256",
    curveName: "nistp256",
    jwkCurveName: "P-256",
    pointByteLength: NISTP256_UNCOMPRESSED_POINT_BYTE_LENGTH,
  },
  {
    algorithm: "ecdsa-sha2-nistp384",
    curveName: "nistp384",
    jwkCurveName: "P-384",
    pointByteLength: NISTP384_UNCOMPRESSED_POINT_BYTE_LENGTH,
  },
  {
    algorithm: "ecdsa-sha2-nistp521",
    curveName: "nistp521",
    jwkCurveName: "P-521",
    pointByteLength: NISTP521_UNCOMPRESSED_POINT_BYTE_LENGTH,
  },
]

function computeExpectedFingerprint(buffer: Buffer): string {
  const hash = createHash("sha256").update(buffer).digest("base64")
  return `SHA256:${hash.replaceAll("=", "")}`
}

describe("readHostFingerprintViaSsh2", () => {
  it("derives the OpenSSH fingerprint from the ssh2 hostVerifier key", async () => {
    const hostKey = buildEd25519HostKeyBuffer()
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
      fingerprint: computeExpectedFingerprint(hostKey),
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

  it.each(ECDSA_FIXTURE_SPECS)(
    "accepts $algorithm host keys when the wire blob is structurally valid",
    async (spec) => {
      const hostKey = buildEcdsaHostKeyBuffer(spec)
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
        algorithm: spec.algorithm,
        fingerprint: computeExpectedFingerprint(hostKey),
      })
    }
  )

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
    const hostKey = Buffer.concat([createWireString("ssh-bogus"), Buffer.from("payload")])

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

  // R-0000128: ssh-rsa is intentionally absent from the host-key allowlist
  // because we cannot enforce a 2048-bit modulus floor on the wire blob in a
  // pre-handshake host-verifier callback while keeping the validation logic
  // minimal. Any ssh-rsa scan must be rejected with the unsupported-algorithm
  // error so operators are forced to pin a verified value out of band.
  it("rejects ssh-rsa host keys as unsupported", async () => {
    const hostKey = Buffer.concat([
      createWireString("ssh-rsa"),
      createWireString(Buffer.from([0x01, 0x00, 0x01])),
      createWireString(Buffer.alloc(256, 1)),
    ])

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
    ).rejects.toThrow(/unsupported SSH host key algorithm "ssh-rsa"/v)
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

  // R-0000128: structural validation of the wire blob.
  it("rejects ed25519 host keys whose public-key field is shorter than 32 bytes", async () => {
    const hostKey = buildEd25519HostKeyBuffer(Buffer.alloc(ED25519_PUBLIC_KEY_BYTE_LENGTH - 1, 2))

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
    ).rejects.toThrow(/malformed "ssh-ed25519" host key blob/v)
  })

  it("rejects ed25519 host keys whose public-key field is longer than 32 bytes", async () => {
    const hostKey = buildEd25519HostKeyBuffer(Buffer.alloc(ED25519_PUBLIC_KEY_BYTE_LENGTH + 1, 3))

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
    ).rejects.toThrow(/malformed "ssh-ed25519" host key blob/v)
  })

  it("rejects ed25519 host keys with trailing data after the public key", async () => {
    const hostKey = Buffer.concat([buildEd25519HostKeyBuffer(), Buffer.from([0x00])])

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
    ).rejects.toThrow(/trailing data after public key/v)
  })

  it("rejects ed25519 host keys whose buffer ends after the algorithm label", async () => {
    const hostKey = createWireString("ssh-ed25519")

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
    ).rejects.toThrow(/missing or truncated public-key field/v)
  })

  it("rejects ECDSA host keys whose curve identifier does not match the algorithm", async () => {
    const point = buildEcdsaPointFromGeneratedKey("P-256")
    const hostKey = Buffer.concat([
      createWireString("ecdsa-sha2-nistp256"),
      createWireString("nistp384"),
      createWireString(point),
    ])

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
    ).rejects.toThrow(/curve identifier "nistp384" does not match "nistp256"/v)
  })

  it("rejects ECDSA host keys whose EC point is the wrong length", async () => {
    const wrongLengthPoint = Buffer.concat([
      Buffer.from([UNCOMPRESSED_EC_POINT_PREFIX]),
      Buffer.alloc(NISTP256_UNCOMPRESSED_POINT_BYTE_LENGTH - 2, 0xaa),
    ])
    const hostKey = Buffer.concat([
      createWireString("ecdsa-sha2-nistp256"),
      createWireString("nistp256"),
      createWireString(wrongLengthPoint),
    ])

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
    ).rejects.toThrow(/EC point/v)
  })

  it("rejects ECDSA host keys whose EC point is not in uncompressed form", async () => {
    const compressedPoint = Buffer.concat([
      Buffer.from([0x02]),
      Buffer.alloc(NISTP256_UNCOMPRESSED_POINT_BYTE_LENGTH - 1, 0xaa),
    ])
    const hostKey = Buffer.concat([
      createWireString("ecdsa-sha2-nistp256"),
      createWireString("nistp256"),
      createWireString(compressedPoint),
    ])

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
    ).rejects.toThrow(/EC point is not in uncompressed form/v)
  })

  it("rejects ECDSA host keys whose EC point is not on the expected curve", async () => {
    const offCurvePoint = Buffer.concat([
      Buffer.from([UNCOMPRESSED_EC_POINT_PREFIX]),
      Buffer.alloc(NISTP256_UNCOMPRESSED_POINT_BYTE_LENGTH - 1, 0),
    ])
    const hostKey = Buffer.concat([
      createWireString("ecdsa-sha2-nistp256"),
      createWireString("nistp256"),
      createWireString(offCurvePoint),
    ])

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
    ).rejects.toThrow(/EC point is not on the expected curve/v)
  })

  it("settles host key verifier errors raised from an asynchronous ssh2 callback", async () => {
    // Wire-format buffer with algorithm "ssh-bogus" (length-prefixed ASCII).
    const hostKey = Buffer.concat([createWireString("ssh-bogus"), Buffer.from("payload")])

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
      // The TCP connect watchdog fires first at readyTimeoutMs = 5000ms,
      // before the half-open watchdog at readyTimeoutMs * 2 = 10000ms.
      await vi.advanceTimersByTimeAsync(5001)
      await expect(promise).rejects.toThrow(/host key scan TCP connect timed out after 5000ms/v)

      expect(fakeClient.removeAllListeners).toHaveBeenCalled()
    } finally {
      vi.useRealTimers()
    }
  })

  // R-0000188: ssh2's readyTimeout covers only the SSH handshake; an
  // explicit TCP connect timeout must surface dropped SYN packets quickly,
  // before falling through to the half-open watchdog at 2x.
  it("rejects with a TCP connect timeout before the half-open watchdog fires", async () => {
    vi.useFakeTimers()

    const fakeClient = createFakeHostKeyClient(() => {
      // Simulate a dropped SYN: ssh2 never reports anything.
    })

    try {
      const promise = readHostFingerprintViaSsh2("example.com", {
        clientFactory: () => useFakeHostKeyClient(fakeClient),
        readyTimeoutMs: 3000,
      })

      promise.catch(() => {
        // Swallow until the assertion observes it.
      })
      // Advance just past the TCP connect watchdog at readyTimeoutMs.
      await vi.advanceTimersByTimeAsync(3001)
      await expect(promise).rejects.toThrow(/TCP connect timed out after 3000ms/v)
    } finally {
      vi.useRealTimers()
    }
  })

  // R-0000187: cleanupClient must install a no-op error listener before
  // removing the original listeners so that late error events emitted during
  // client.end() (half-closed socket, ssh2-layer throws) do not bubble up
  // as uncaught errors and crash the process.
  it("absorbs late error events emitted during client.end()", async () => {
    const hostKey = buildEd25519HostKeyBuffer()
    const fakeClient = createFakeHostKeyClient((config, client) => {
      callHostVerifier(config, hostKey)
      setImmediate(() => {
        client.handlers.error(new Error("Host denied"))
      })
    })
    // After removeAllListeners + on("error", noop), end() emits a late
    // error. The no-op listener installed by cleanupClient must absorb it.
    fakeClient.end.mockImplementation((): void => {
      fakeClient.handlers.error(new Error("late socket teardown error"))
    })

    await expect(
      readHostFingerprintViaSsh2("example.com", {
        clientFactory: () => useFakeHostKeyClient(fakeClient),
      })
    ).resolves.toMatchObject({ algorithm: "ssh-ed25519" })

    // Two error listeners observed in total: the original from
    // registerFingerprintListeners and the no-op installed during cleanup.
    const errorListenerRegistrations = fakeClient.on.mock.calls.filter(
      ([event]) => event === "error"
    )
    expect(errorListenerRegistrations.length).toBeGreaterThanOrEqual(2)
  })

  // R-0000127: when the close handler resolves first, the watchdog must be
  // cleared so it cannot keep the event loop alive or fire spuriously.
  it("clears the watchdog on a successful resolution", async () => {
    const hostKey = buildEd25519HostKeyBuffer()

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
