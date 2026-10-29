// THROWAWAY SPIKE (issue #254): child process for the lifecycle proofs (H5).
// Usage: node lifecycle-child.mjs <mode>; connection data via SPIKE_CHILD_* env.
import { readFileSync } from "node:fs"
import { createRequire } from "node:module"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"

const require = createRequire(import.meta.url)
const packageDir = join(dirname(fileURLToPath(import.meta.url)), "..", "..")
const mode = process.argv[2]
const env = process.env
const options = {
  host: env.SPIKE_CHILD_HOST,
  port: Number(env.SPIKE_CHILD_PORT),
  user: env.SPIKE_CHILD_USER,
}
const keyPath = env.SPIKE_CHILD_KEY
const say = (line) => process.stdout.write(`${line} ${Date.now()}\n`)

if (mode.startsWith("ssh2-")) {
  const { Client } = require("ssh2")
  const client = new Client()
  client.on("ready", () => {
    if (mode === "ssh2-idle") say("IDLE")
    if (mode === "ssh2-close") {
      client.end()
      say("CLOSED")
    }
  })
  client.on("error", (error) => {
    process.stderr.write(`ssh2 error: ${error.message}\n`)
    process.exitCode = 2
  })
  client.connect({
    ...options,
    username: options.user,
    privateKey: readFileSync(keyPath),
    hostVerifier: () => true,
  })
} else {
  const ssh = require(join(packageDir, "index.js"))
  const session = await ssh.connect(
    { ...options, privateKey: readFileSync(keyPath) },
    async () => true
  )
  switch (mode) {
    case "destroy-exit": {
      const channel = await session.exec(env.SPIKE_CHILD_COMMAND ?? "sleep 60")
      channel.stdout.resume()
      channel.stderr.resume()
      await new Promise((r) => setTimeout(r, 500))
      say("READY")
      session.destroy()
      process.exit(0)
      break
    }
    case "destroy-natural": {
      const channel = await session.exec("sleep 60")
      channel.stdout.resume()
      channel.stderr.resume()
      await new Promise((r) => setTimeout(r, 300))
      session.destroy()
      say("DESTROYED")
      break
    }
    case "close": {
      const channel = await session.exec("echo ok")
      channel.stdin.end()
      channel.stdout.resume()
      await channel.done
      await session.close()
      say("CLOSED")
      break
    }
    case "idle":
      say("IDLE")
      break
    default:
      process.stderr.write(`unknown mode ${mode}\n`)
      process.exit(3)
  }
}
