// Child process of the lifecycle proofs (integration H5 and the smoke test):
// connects with a key file, runs one scenario and prints a marker line
// `<MARKER> [fields...] <epoch ms>` the parent times the exit against.
//
//   node lifecycle-child.mjs <mode>
//
// Modes:
//   destroy-exit            exec COMMAND, then destroy() + process.exit(0)
//   destroy-exit-streaming  exec COMMAND (endless output) with a stdout
//                           listener attached, after STREAM_BYTES destroy()
//                           + process.exit(0) while data is still arriving
//   destroy-natural         exec COMMAND, then destroy(); the process must end
//                           on its own
//   close                   exec COMMAND to completion, close(); ends on its own
//   idle                    connect and do nothing; the connection keeps the
//                           process alive
//
// Environment: SSH_NATIVE_CHILD_HOST, _PORT, _USER, _KEY (private key file),
// _HOST_KEY (base64 host key blob), _COMMAND, _STREAM_BYTES.
import { readFileSync } from "node:fs"
import { createRequire } from "node:module"
import { setTimeout as sleep } from "node:timers/promises"

const require = createRequire(import.meta.url)
/** @type {typeof import("../../index.js")} */
const binding = require("../../index.js")

const { env } = process
const mode = process.argv[2]
const command = env.SSH_NATIVE_CHILD_COMMAND ?? "true"
const say = (/** @type {string} */ line) => process.stdout.write(`${line} ${Date.now()}\n`)

const session = await binding.connect(
  {
    host: String(env.SSH_NATIVE_CHILD_HOST),
    port: Number(env.SSH_NATIVE_CHILD_PORT),
    privateKey: readFileSync(String(env.SSH_NATIVE_CHILD_KEY)),
    user: String(env.SSH_NATIVE_CHILD_USER),
  },
  (info) => info.keyBase64 === env.SSH_NATIVE_CHILD_HOST_KEY
)

/** @returns the channel of COMMAND with stdout and stderr drained */
async function start() {
  const channel = await session.exec(command)
  channel.stdin.end()
  channel.stdout.resume()
  channel.stderr.resume()
  return channel
}

/**
 * Keeps a stdout listener attached and resolves after `threshold` bytes.
 *
 * @param channel the streaming channel
 * @param threshold bytes to wait for
 * @returns the bytes received so far
 */
function streamed(channel, threshold) {
  return new Promise((resolve) => {
    let received = 0
    channel.stdout.on("data", (/** @type {Buffer} */ chunk) => {
      received += chunk.length
      if (received >= threshold) resolve(received)
    })
  })
}

/** @type {Record<string, () => Promise<void>>} */
const MODES = {
  async close() {
    const channel = await start()
    await channel.exit
    await session.close()
    say("CLOSED")
  },
  "destroy-exit": async () => {
    await start()
    await sleep(300)
    say("READY")
    session.destroy()
    // eslint-disable-next-line node/no-process-exit -- the scenario under test
    process.exit(0)
  },
  "destroy-exit-streaming": async () => {
    const channel = await session.exec(command)
    channel.stdin.end()
    channel.stderr.resume()
    const received = await streamed(channel, Number(env.SSH_NATIVE_CHILD_STREAM_BYTES ?? 524_288))
    // The data listener stays attached: native callbacks keep queueing
    // while destroy() and process.exit() run.
    say(`READY ${received}`)
    session.destroy()
    // eslint-disable-next-line node/no-process-exit -- the scenario under test
    process.exit(0)
  },
  "destroy-natural": async () => {
    await start()
    await sleep(300)
    session.destroy()
    say("DESTROYED")
  },
  async idle() {
    say("IDLE")
  },
}

const scenario = MODES[String(mode)]
if (!scenario) throw new Error(`unknown mode ${mode}`)
await scenario()
