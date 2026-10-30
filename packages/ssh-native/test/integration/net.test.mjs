// The TCP helpers of the harness itself (lib/net.mjs), without a target: a
// readiness probe must settle when a peer accepts and closes (a Docker port
// proxy before sshd listens) or accepts and stays silent, and freePorts()
// must hand out distinct ports.
import assert from "node:assert/strict"
import { createServer } from "node:net"
import { describe, it } from "node:test"

import { within } from "../helpers/binding.mjs"
import { freePorts, probeBanner, waitForBanner } from "./lib/net.mjs"

/**
 * @param onConnection what the server does with each accepted socket
 * @returns the listening server and its port
 */
async function listen(onConnection) {
  /** @type {Set<import("node:net").Socket>} */
  const sockets = new Set()
  const server = createServer((socket) => {
    sockets.add(socket)
    socket.on("error", () => {})
    socket.once("close", () => sockets.delete(socket))
    onConnection(socket)
  })
  await new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(undefined))
  })
  const { port } = /** @type {import("node:net").AddressInfo} */ (server.address())
  const close = () =>
    new Promise((resolve) => {
      for (const socket of sockets) socket.destroy()
      server.close(() => resolve(undefined))
    })
  return { close, port }
}

describe("harness TCP helpers", () => {
  it("a probe settles with false when the peer accepts and closes", async () => {
    const server = await listen((socket) => socket.end())
    try {
      assert.equal(await within(probeBanner(server.port, 60_000), 2000, "probe"), false)
      await assert.rejects(within(waitForBanner(server.port, 500), 3000, "waitForBanner"), {
        message: /no SSH banner/v,
      })
    } finally {
      await server.close()
    }
  })

  it("a probe settles with false when the peer accepts and stays silent", async () => {
    const server = await listen(() => {})
    try {
      assert.equal(await within(probeBanner(server.port, 200), 2000, "probe"), false)
      await assert.rejects(within(waitForBanner(server.port, 500), 3000, "waitForBanner"), {
        message: /no SSH banner/v,
      })
    } finally {
      await server.close()
    }
  })

  it("a probe sees an SSH banner", async () => {
    const server = await listen((socket) => socket.write("SSH-2.0-probe\r\n"))
    try {
      assert.equal(await probeBanner(server.port), true)
      await waitForBanner(server.port, 2000)
    } finally {
      await server.close()
    }
  })

  it("freePorts() returns distinct ports", async () => {
    const ports = await freePorts(4)
    assert.equal(new Set(ports).size, 4)
  })
})
