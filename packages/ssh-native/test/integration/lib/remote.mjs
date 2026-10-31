// Connecting to the target sshd and running commands on it.
import { createHash } from "node:crypto"
import { readFileSync } from "node:fs"

import { binding, collect } from "../../helpers/binding.mjs"
import { fixtures, target } from "./context.mjs"

/**
 * A portable SHA-256 of stdin: `sha256sum` (Linux) or `shasum -a 256`
 * (macOS); prints `<hex>  -`.
 */
export const SHA256_STDIN =
  "if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi"

/** @returns a verifier that accepts exactly the run's host key */
export function pinnedVerifier() {
  const expected = fixtures().hostKeyBase64
  return (/** @type {import("../../../index.js").HostKeyInfo} */ info) =>
    info.kind === "key" && info.keyBase64 === expected
}

/**
 * @param [overrides] connect options to add or replace (`port` included)
 * @returns options for the target's main profile
 */
export function targetOptions(overrides = {}) {
  const { host, ports, user } = target()
  return { host, port: ports.main, user, ...overrides }
}

/**
 * Logs in with a private key file.
 *
 * @param keyPath private key path
 * @param [overrides] connect options
 * @returns the session
 */
export function connectWithKeyFile(keyPath, overrides = {}) {
  const privateKey = readFileSync(keyPath)
  return binding.connect(targetOptions({ privateKey, ...overrides }), pinnedVerifier())
}

/**
 * Logs in through an ssh-agent.
 *
 * @param socket agent socket path
 * @param [overrides] connect options
 * @returns the session
 */
export function connectWithAgent(socket, overrides = {}) {
  return binding.connect(targetOptions({ agent: socket, ...overrides }), pinnedVerifier())
}

/**
 * @typedef {object} RunResult
 * @property {number | null} code exit code
 * @property {string | null} signal raw signal name
 * @property {boolean} disconnected whether the connection was lost
 * @property {string} stdout output
 * @property {string} stderr error output
 */

/**
 * Runs a command to completion.
 *
 * @param session an open session
 * @param command the remote command
 * @param [stdin] data for stdin; stdin is closed either way
 * @returns exit and output
 */
export async function run(session, command, stdin) {
  const channel = await session.exec(command)
  channel.stdin.end(stdin)
  const [stdout, stderr, exit] = await Promise.all([
    collect(channel.stdout),
    collect(channel.stderr),
    channel.exit,
  ])
  return { ...exit, stderr: stderr.toString(), stdout: stdout.toString() }
}

/**
 * @param publicKeyPath a `.pub` file
 * @returns its `SHA256:...` fingerprint, as `ssh-add -l` prints it
 */
export function fingerprint(publicKeyPath) {
  const [, blob] = readFileSync(publicKeyPath, "utf8").trim().split(/\s+/v)
  const digest = createHash("sha256").update(Buffer.from(blob, "base64")).digest("base64")
  return `SHA256:${digest.replaceAll("=", "")}`
}
