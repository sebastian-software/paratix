// A private ssh-agent per test: its own socket in the run directory, the
// given keys added, killed by `stop()` (and at the latest when the test
// process exits).
import { spawn } from "node:child_process"
import { once } from "node:events"
import { existsSync, mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { setTimeout as sleep } from "node:timers/promises"

import { descriptor } from "./context.mjs"
import { runTool } from "./tools.mjs"

const SOCKET_TIMEOUT_MS = 5000
const POLL_MS = 20

/** @type {Set<import("node:child_process").ChildProcess>} */
const running = new Set()
process.once("exit", () => {
  for (const child of running) child.kill("SIGKILL")
})

/**
 * @typedef {object} Agent
 * @property {string} socket the agent socket (SSH_AUTH_SOCK)
 * @property {Record<string, string>} added per key: `added` or the ssh-add error
 * @property {string[]} identities `ssh-add -L` lines
 * @property {() => Promise<void>} stop kills the agent
 */

/**
 * @param socket agent socket
 * @param keyPath private key to add (ssh-add also loads `<key>-cert.pub`)
 * @returns `added` or the ssh-add error
 */
async function addKey(socket, keyPath) {
  const env = { ...process.env, SSH_AUTH_SOCK: socket }
  try {
    await runTool("ssh-add", [keyPath], { env })
    return "added"
  } catch (error) {
    return `ssh-add failed: ${error instanceof Error ? error.message : String(error)}`
  }
}

/**
 * @param socket agent socket
 * @returns the `ssh-add -L` lines (empty if the agent holds nothing)
 */
async function listIdentities(socket) {
  const env = { ...process.env, SSH_AUTH_SOCK: socket }
  const listing = await runTool("ssh-add", ["-L"], { env }).catch(() => "")
  return listing.split("\n").filter((line) => line.startsWith("ssh-") || line.startsWith("ecdsa-"))
}

/**
 * @param socket the socket path
 * @returns resolves once the agent created it
 */
async function waitForSocket(socket) {
  const deadline = Date.now() + SOCKET_TIMEOUT_MS
  while (!existsSync(socket)) {
    if (Date.now() > deadline) throw new Error("ssh-agent did not create its socket")
    // eslint-disable-next-line no-await-in-loop -- polling one file
    await sleep(POLL_MS)
  }
}

/**
 * Starts an agent and adds the keys, one after another.
 *
 * @param keyPaths private keys to add
 * @returns socket, ssh-add outcomes, identities and `stop()`
 */
export async function startAgent(keyPaths) {
  // Short paths: macOS limits Unix socket paths to 104 bytes.
  const dir = mkdtempSync(join(descriptor.runDir || tmpdir(), "a-"))
  const socket = join(dir, "s")
  const child = spawn("ssh-agent", ["-D", "-a", socket], { stdio: "ignore" })
  running.add(child)
  const stop = async () => {
    running.delete(child)
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, "exit")
      child.kill("SIGTERM")
      await exited
    }
    rmSync(dir, { force: true, recursive: true })
  }
  try {
    await waitForSocket(socket)
    /** @type {Record<string, string>} */
    const added = {}
    for (const keyPath of keyPaths) {
      // eslint-disable-next-line no-await-in-loop -- keeps the agent's identity order
      added[keyPath] = await addKey(socket, keyPath)
    }
    return { added, identities: await listIdentities(socket), socket, stop }
  } catch (error) {
    await stop()
    throw error
  }
}
