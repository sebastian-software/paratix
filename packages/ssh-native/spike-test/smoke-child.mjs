// THROWAWAY SPIKE (issue #254): child process of smoke.mjs (copied alongside it).
// Usage: node smoke-child.mjs <panic|destroy-exit-sleep|destroy-exit-stream>
// Env: SMOKE_INDEX, SMOKE_PORT, SMOKE_KEY, SMOKE_HOST_KEY (and optionally
// PARATIX_SSH_NATIVE_PATH, honoured by index.js).
import { readFileSync } from "node:fs"
import { createRequire } from "node:module"

const require = createRequire(import.meta.url)
const binding = require(process.env.SMOKE_INDEX)
const mode = process.argv[2]
const say = (line) => process.stdout.write(`${line} ${Date.now()}\n`)

if (mode === "panic") {
  await binding.internalPanicProbe().then(
    () => say(`PANIC ${JSON.stringify({ code: "RESOLVED" })}`),
    (error) => say(`PANIC ${JSON.stringify({ code: error.code, message: error.message })}`)
  )
} else {
  const session = await binding.connect(
    {
      host: "127.0.0.1",
      port: Number(process.env.SMOKE_PORT),
      user: "smoke",
      privateKey: readFileSync(process.env.SMOKE_KEY),
    },
    async (info) => info.keyBase64 === process.env.SMOKE_HOST_KEY
  )
  if (mode === "destroy-exit-sleep") {
    const channel = await session.exec("smoke-sleep")
    channel.stdout.resume()
    channel.stderr.resume()
    await new Promise((r) => setTimeout(r, 200))
  } else if (mode === "destroy-exit-stream") {
    const channel = await session.exec("smoke-stream")
    channel.stderr.resume()
    let received = 0
    // The listener stays attached; native callbacks keep queueing until exit.
    await new Promise((resolve) => {
      channel.stdout.on("data", (chunk) => {
        received += chunk.length
        if (received >= 512 * 1024) resolve()
      })
    })
  } else {
    process.stderr.write(`unknown mode ${mode}\n`)
    process.exit(3)
  }
  say("READY")
  session.destroy()
  process.exit(0)
}
