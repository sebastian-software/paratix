// TCP helpers of the integration harness.
import { createConnection, createServer } from "node:net"
import { setTimeout as sleep } from "node:timers/promises"

const POLL_MS = 100
const PROBE_TIMEOUT_MS = 2000

/**
 * @param server a server to close
 * @returns resolves once it is closed
 */
function closeServer(server) {
  return new Promise((resolve) => {
    server.close(() => resolve(undefined))
  })
}

/**
 * Reserves `count` distinct TCP ports that were free on 127.0.0.1 a moment
 * ago. Every listener stays open until all ports are taken, so the kernel
 * cannot hand out the same port twice; they are released before returning.
 *
 * @param count how many ports
 * @returns the distinct ports
 */
export async function freePorts(count) {
  /** @type {import("node:net").Server[]} */
  const servers = []
  try {
    for (let index = 0; index < count; index += 1) {
      const server = createServer()
      servers.push(server)
      // eslint-disable-next-line no-await-in-loop -- each listener stays open for the next one
      await new Promise((resolve, reject) => {
        server.once("error", reject)
        server.listen(0, "127.0.0.1", () => resolve(undefined))
      })
    }
    const ports = servers.map(
      (server) => /** @type {import("node:net").AddressInfo} */ (server.address()).port
    )
    if (new Set(ports).size !== count) throw new Error(`ports not distinct: ${ports.join(", ")}`)
    return ports
  } finally {
    await Promise.all(
      servers.filter((server) => server.listening).map((server) => closeServer(server))
    )
  }
}

/**
 * One probe. It settles on the first of: data (the banner check), an
 * error, the peer closing or ending the connection (e.g. a Docker port
 * proxy that accepts before sshd listens), or a hard timer that does not
 * depend on socket activity.
 *
 * @param port local port
 * @param timeoutMs deadline of this probe
 * @returns whether an SSH server greets with its banner
 */
export function probeBanner(port, timeoutMs = PROBE_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const socket = createConnection({ host: "127.0.0.1", port })
    let settled = false
    const done = (/** @type {boolean} */ ok) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.destroy()
      resolve(ok)
    }
    const timer = setTimeout(() => done(false), timeoutMs)
    socket.once("data", (data) => done(data.toString("latin1").startsWith("SSH-")))
    socket.once("error", () => done(false))
    socket.once("end", () => done(false))
    socket.once("close", () => done(false))
  })
}

/**
 * @typedef {object} WaitOptions
 * @property {import("node:child_process").ChildProcess} [process] the server
 *   process; its exit ends the wait early
 * @property {AbortSignal} [signal] ends the wait (teardown)
 */

/**
 * Waits until an SSH server on 127.0.0.1:`port` sends its banner.
 *
 * @param port local port
 * @param timeoutMs deadline
 * @param [options] server process and abort signal (WaitOptions)
 * @returns resolves once the banner arrived
 */
export async function waitForBanner(port, timeoutMs, options = {}) {
  const { process, signal } = /** @type {WaitOptions} */ (options)
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    signal?.throwIfAborted()
    if (process && (process.exitCode !== null || process.signalCode !== null)) {
      throw new Error(`the server exited early (${process.exitCode ?? process.signalCode})`)
    }
    const probeMs = Math.max(1, Math.min(PROBE_TIMEOUT_MS, deadline - Date.now()))
    // eslint-disable-next-line no-await-in-loop -- polling one port in order
    if (await probeBanner(port, probeMs)) return
    // eslint-disable-next-line no-await-in-loop -- polling interval
    await sleep(POLL_MS)
  }
  throw new Error(`no SSH banner on 127.0.0.1:${port} within ${timeoutMs} ms`)
}

/**
 * Waits until every port sends an SSH banner.
 *
 * @param ports local ports
 * @param timeoutMs deadline per port
 * @param [options] server process and abort signal (WaitOptions)
 * @returns resolves once all ports greeted
 */
export async function waitForBanners(ports, timeoutMs, options = {}) {
  await Promise.all(ports.map((port) => waitForBanner(port, timeoutMs, options)))
}
