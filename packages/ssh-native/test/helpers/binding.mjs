// Loads the binding under test, failing with a clear message when the
// native binary has not been built yet.
import { existsSync } from "node:fs"
import { createRequire } from "node:module"
import { join } from "node:path"
import { setTimeout as sleep } from "node:timers/promises"

const require = createRequire(import.meta.url)

export const PACKAGE_DIR = join(import.meta.dirname, "..", "..")
export const INDEX_PATH = join(PACKAGE_DIR, "index.js")

/** @type {typeof import("../../loader.js")} */
const loader = require(join(PACKAGE_DIR, "loader.js"))

export const BINARY_PATH = join(PACKAGE_DIR, `ssh-native.${loader.currentTarget()}.node`)

if (!existsSync(BINARY_PATH)) {
  throw new Error(
    `native binary ${BINARY_PATH} is missing: run \`pnpm --filter @paratix/ssh-native build\` ` +
      "(needs the Rust toolchain from packages/ssh-native/rust-toolchain.toml) before the tests"
  )
}

/** @type {typeof import("../../index.js")} */
export const binding = require(INDEX_PATH)

/** @typedef {import("../../index.js").HostVerifier} HostVerifier */
/** @typedef {import("../../index.js").ConnectOptions} ConnectOptions */

/**
 * @param server the test server
 * @returns accepts exactly the host key of `server`
 */
export function trustServer(server) {
  return (info) => info.keyBase64 === server.hostKeyBase64
}

/**
 * Connects as the test user with a client key.
 *
 * @param server the test server
 * @param key a clientKey()
 * @param [options] overrides
 * @returns the session
 */
export function connectWithKey(server, key, options = {}) {
  const { verifyHost = trustServer(server), ...overrides } = options
  return binding.connect(
    {
      host: server.host,
      port: server.port,
      privateKey: Buffer.from(key.privateKey),
      user: "tester",
      ...overrides,
    },
    verifyHost
  )
}

/**
 * @param readable the stream
 * @returns everything it emitted
 */
export async function collect(readable) {
  /** @type {Buffer[]} */
  const chunks = []
  for await (const chunk of readable) chunks.push(/** @type {Buffer} */ (chunk))
  return Buffer.concat(chunks)
}

/**
 * @param ms milliseconds
 * @returns resolves after `ms`
 */
export function delay(ms) {
  return sleep(ms)
}

/**
 * Settles like `promise`, or rejects if that takes longer than `ms`.
 *
 * @template T
 * @param promise the operation under test
 * @param ms deadline in milliseconds
 * @param label what is awaited, for the failure message
 * @returns the outcome of `promise`
 */
export async function within(promise, ms, label) {
  /** @type {ReturnType<typeof setTimeout> | undefined} */
  let timer
  const deadline = new Promise((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} did not settle within ${ms} ms`)), ms)
  })
  try {
    return await Promise.race([promise, deadline])
  } finally {
    clearTimeout(timer)
  }
}
