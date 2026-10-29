// Child process of verifier-abort.test.mjs. It holds no handle of its own
// except the SSH connection attempt (mode `never`), or additionally the
// timer that settles the verifier late (mode `late`).
import { createRequire } from "node:module"

const require = createRequire(import.meta.url)
/** @type {typeof import("../../index.js")} */
const binding = require("../../index.js")
const mode = process.argv[2]
const readyTimeoutMs = Number(process.env.READY_TIMEOUT_MS)
const say = (/** @type {string} */ line) => process.stdout.write(`${line}\n`)

process.on("unhandledRejection", (reason) => {
  process.stderr.write(`unhandledRejection: ${String(reason)}\n`)
})

/** @returns settles never (`never`) or after the timeout (`late`) */
function verifyHost() {
  /** @type {PromiseWithResolvers<boolean>} */
  const { promise, resolve } = Promise.withResolvers()
  if (mode === "late") {
    setTimeout(() => {
      say("LATE-SETTLED")
      resolve(true)
    }, readyTimeoutMs + 500)
  }
  return promise
}

const started = Date.now()
try {
  await binding.connect(
    {
      host: "127.0.0.1",
      password: Buffer.from("x"),
      port: Number(process.env.SERVER_PORT),
      readyTimeoutMs,
      user: "tester",
    },
    verifyHost
  )
  say(JSON.stringify({ outcome: "connected" }))
} catch (error) {
  say(JSON.stringify({ code: error.code, elapsedMs: Date.now() - started, outcome: "rejected" }))
}
