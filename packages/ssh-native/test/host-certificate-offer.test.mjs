import assert from "node:assert/strict"
import { once } from "node:events"
import { createServer } from "node:net"
import { describe, it } from "node:test"

import { binding } from "./helpers/binding.mjs"

/**
 * Captures the real initial KEXINIT before sending any server host key.
 * This proves the offer for scan and each independent connect attempt.
 *
 * @param operation starts a native handshake against the capture socket
 * @returns the client's host-key algorithm list
 */
async function captureHostAlgorithms(operation) {
  let capture
  const captured = new Promise((resolve) => {
    capture = resolve
  })
  const sockets = new Set()
  const server = createServer((socket) => {
    sockets.add(socket)
    socket.on("close", () => sockets.delete(socket))
    socket.on("error", () => {})
    socket.write("SSH-2.0-HostCertificateOfferTest\r\n")
    let received = Buffer.alloc(0)
    let banner = false
    socket.on("data", (chunk) => {
      received = Buffer.concat([received, chunk])
      if (!banner) {
        const end = received.indexOf("\n")
        if (end === -1) return
        received = received.subarray(end + 1)
        banner = true
      }
      if (received.length < 5 || received.length < 4 + received.readUInt32BE(0)) return
      assert.equal(received[5], 20, "first SSH packet is KEXINIT")
      // Packet header (5), message type (1), cookie (16), then name-lists.
      const kexOffset = 22
      const hostOffset = kexOffset + 4 + received.readUInt32BE(kexOffset)
      const length = received.readUInt32BE(hostOffset)
      capture(
        received
          .subarray(hostOffset + 4, hostOffset + 4 + length)
          .toString()
          .split(",")
      )
      socket.destroy()
    })
  })
  server.listen(0, "127.0.0.1")
  await once(server, "listening")
  const address = server.address()
  assert.ok(address && typeof address === "object")
  try {
    const attempt = operation({ host: "127.0.0.1", port: address.port })
    await assert.rejects(attempt)
    return await captured
  } finally {
    for (const socket of sockets) socket.destroy()
    server.close()
    await once(server, "close")
  }
}

const RAW = [
  "ssh-ed25519",
  "ecdsa-sha2-nistp256",
  "ecdsa-sha2-nistp384",
  "ecdsa-sha2-nistp521",
  "rsa-sha2-512",
  "rsa-sha2-256",
  "ssh-rsa",
]
const CERTIFICATES = [
  "ssh-ed25519-cert-v01@openssh.com",
  "ecdsa-sha2-nistp256-cert-v01@openssh.com",
  "ecdsa-sha2-nistp384-cert-v01@openssh.com",
  "ecdsa-sha2-nistp521-cert-v01@openssh.com",
  "rsa-sha2-512-cert-v01@openssh.com",
  "rsa-sha2-256-cert-v01@openssh.com",
]

const offer = (hostCertificates) =>
  captureHostAlgorithms((target) =>
    binding.connect(
      {
        ...target,
        hostCertificates,
        password: Buffer.from("unused"),
        readyTimeoutMs: 3000,
        user: "unused",
      },
      () => true
    )
  )

describe("host certificate offer", { timeout: 20_000 }, () => {
  it("opts in per connection, ahead of the unchanged raw algorithms", async () => {
    assert.deepEqual(await offer(undefined), RAW)
    assert.deepEqual(await offer(true), [...CERTIFICATES, ...RAW])
    assert.deepEqual(await offer(false), RAW)
    assert.deepEqual(await offer(undefined), RAW)
  })

  it("scan never offers host certificates", async () => {
    assert.deepEqual(
      await captureHostAlgorithms((target) =>
        binding.scan({
          ...target,
          timeoutMs: 3000,
        })
      ),
      RAW
    )
  })

  it("rejects an invalid opt-in before connecting and clears credentials", async () => {
    const password = Buffer.from("unused")
    await assert.rejects(
      binding.connect(
        {
          host: "127.0.0.1",
          hostCertificates: /** @type {boolean} */ (/** @type {unknown} */ ("true")),
          password,
          port: 1,
          user: "unused",
        },
        () => true
      ),
      TypeError
    )
    assert.ok(password.every((byte) => byte === 0))
  })
})
