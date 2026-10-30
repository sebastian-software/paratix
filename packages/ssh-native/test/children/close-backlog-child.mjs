// Child process of exec.test.mjs: opens a channel whose stderr backlog
// piles up in the binding's event queue while the JS thread is busy, then
// closes the session and reports how much stderr arrived before the exit.
import { createRequire } from "node:module"

const require = createRequire(import.meta.url)
/** @type {typeof import("../../index.js")} */
const binding = require("../../index.js")

/**
 * Keeps the JS thread busy, so native events queue up meanwhile.
 *
 * @param ms how long
 */
function busy(ms) {
  const until = Date.now() + ms
  while (Date.now() < until) {
    // Spin.
  }
}

/** Runs the scenario and prints the report. */
async function main() {
  const session = await binding.connect(
    {
      host: "127.0.0.1",
      port: Number(process.env.SERVER_PORT),
      privateKey: Buffer.from(String(process.env.CLIENT_KEY)),
      user: "tester",
    },
    () => true
  )
  const channel = await session.exec(`backlog ${process.env.BACKLOG_SIZE}`)
  let received = 0
  let receivedAtExit = -1
  channel.stderr.on("data", (chunk) => {
    received += chunk.length
  })
  channel.stdout.resume()
  const exitSeen = channel.exit.then(() => {
    receivedAtExit = received
  })
  // The server sends the whole backlog meanwhile; it queues in the binding.
  busy(Number(process.env.BUSY_MS))
  const closing = session.close()
  // The native close completes meanwhile; its result queues as well.
  busy(500)
  await closing
  const exit = await channel.exit
  await exitSeen
  process.stdout.write(`${JSON.stringify({ exit, received, receivedAtExit })}\n`)
}

await main()
