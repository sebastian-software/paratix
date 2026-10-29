// THROWAWAY SPIKE (issue #254): per-target prebuild smoke test.
//
//   node smoke.mjs                      # loads index.js next to this file (or ../index.js)
//   node smoke.mjs ./ssh-native.linux-x64-musl.node   # loads a given binary via index.js
//   node smoke.mjs ./dir-with-index-js  # loads <dir>/index.js
//
// Self-contained: needs only `ssh2` (resolvable from this file or the working
// directory) and `smoke-child.mjs` next to this file. Against an in-process
// ssh2 Server it checks: scan(), ed25519 key login (signature verified by the
// server), exec with exit code, panic -> INTERNAL (silent), and destroy() +
// process.exit(0) in child processes (idle and streaming exec). It prints one
// JSON line (`{"smoke": ...}`) with the sha256 of the loaded binary; exit 0/1.
import { spawn } from "node:child_process"
import { createHash, createPublicKey, generateKeyPairSync, verify } from "node:crypto"
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs"
import { createRequire } from "node:module"
import { tmpdir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const here = dirname(fileURLToPath(import.meta.url))
const CHILD = join(here, "smoke-child.mjs")
const ITERATIONS = Number(process.env.SMOKE_ITERATIONS ?? 20)
const ABORT_PATTERN = /abort|panic|fatal|terminate called|core dumped|assertion|segmentation/i

function requireSsh2() {
  for (const base of [import.meta.url, join(process.cwd(), "noop.js")]) {
    try {
      return createRequire(base)("ssh2")
    } catch {
      // try next base
    }
  }
  throw new Error(
    "smoke: cannot resolve 'ssh2'; install it next to smoke.mjs or in the working directory"
  )
}

/** Resolves index.js and, for a `.node` argument, routes the loader to it. */
function resolveIndex(arg) {
  const defaultIndex = existsSync(join(here, "index.js"))
    ? join(here, "index.js")
    : join(here, "..", "index.js")
  if (arg && arg.endsWith(".node")) {
    process.env.PARATIX_SSH_NATIVE_PATH = resolve(arg)
    return defaultIndex
  }
  if (!arg) return defaultIndex
  const path = resolve(arg)
  return existsSync(path) && statSync(path).isDirectory() ? join(path, "index.js") : path
}

function sshString(buffer) {
  const length = Buffer.alloc(4)
  length.writeUInt32BE(buffer.length)
  return Buffer.concat([length, buffer])
}

function ed25519Blob(publicKey) {
  const raw = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url")
  return Buffer.concat([sshString(Buffer.from("ssh-ed25519")), sshString(raw)])
}

function startServer(ssh2, clientPublicKey) {
  const { Server, utils } = ssh2
  // RSA PKCS#1 host key, as in startTestSshServer (cli.dist.test.ts).
  const { privateKey: hostKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { format: "pem", type: "pkcs1" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  })
  const clientBlob = ed25519Blob(clientPublicKey)
  const state = { signatureVerified: false, rejectedAuth: 0 }
  const flood = Buffer.alloc(32 * 1024, "smoke-streaming-line\n")
  const server = new Server({ hostKeys: [hostKey] }, (client) => {
    client.on("error", () => {})
    client.on("authentication", (ctx) => {
      if (
        ctx.method !== "publickey" ||
        ctx.key.algo !== "ssh-ed25519" ||
        !ctx.key.data.equals(clientBlob)
      ) {
        state.rejectedAuth += 1
        ctx.reject()
        return
      }
      if (!ctx.signature) {
        ctx.accept() // PK_OK: the client then sends the signed request
        return
      }
      if (verify(null, ctx.blob, clientPublicKey, ctx.signature)) {
        state.signatureVerified = true
        ctx.accept()
      } else {
        state.rejectedAuth += 1
        ctx.reject()
      }
    })
    client.on("ready", () => {
      client.on("session", (accept) => {
        const session = accept()
        session.on("exec", (acceptExec, _reject, info) => {
          const stream = acceptExec()
          stream.on("error", () => {})
          if (info.command === "smoke-sleep") return // stays open and silent
          if (info.command === "smoke-stream") {
            let open = true
            stream.on("close", () => {
              open = false
            })
            const pump = () => {
              while (open && stream.writable && stream.write(flood)) {
                // keep writing until the channel window is full
              }
              if (open && stream.writable) stream.once("drain", pump)
            }
            pump()
            return
          }
          const match = /^exit (\d+)$/.exec(info.command)
          stream.write("smoke exec\n")
          stream.exit(match ? Number(match[1]) : 0)
          stream.end()
        })
      })
    })
  })
  return {
    server,
    state,
    hostKeyBase64: utils.parseKey(hostKey).getPublicSSH().toString("base64"),
  }
}

function runChild(mode, env, marker) {
  return new Promise((resolveRun) => {
    const child = spawn(process.execPath, [CHILD, mode], { env, stdio: ["ignore", "pipe", "pipe"] })
    let stdout = ""
    let stderr = ""
    let markerAt = null
    child.stdout.on("data", (d) => {
      stdout += d
      const line = stdout.split("\n").find((l) => l.startsWith(`${marker} `))
      if (line && markerAt === null) markerAt = Number(line.trim().split(" ").at(-1))
    })
    child.stderr.on("data", (d) => {
      stderr += d
    })
    const killer = setTimeout(() => child.kill("SIGKILL"), 15_000)
    child.on("exit", (code, signal) => {
      clearTimeout(killer)
      resolveRun({ code, signal, stdout, stderr, markerAt, exitAt: Date.now() })
    })
  })
}

async function destroyExitRuns(mode, env) {
  const latencies = []
  for (let i = 0; i < ITERATIONS; i += 1) {
    const result = await runChild(mode, env, "READY")
    if (result.markerAt === null)
      throw new Error(`${mode} run ${i}: no READY (${result.stderr.trim()})`)
    if (result.code !== 0 || result.signal !== null) {
      throw new Error(
        `${mode} run ${i}: code ${result.code} signal ${result.signal} (${result.stderr.trim()})`
      )
    }
    if (result.stderr !== "" || ABORT_PATTERN.test(result.stdout)) {
      throw new Error(`${mode} run ${i}: unexpected output: ${result.stderr.trim()}`)
    }
    latencies.push(result.exitAt - result.markerAt)
  }
  return {
    runs: ITERATIONS,
    allExitCode0SignalNullStderrEmpty: true,
    maxExitLatencyMs: Math.max(...latencies),
  }
}

async function main() {
  const indexPath = resolveIndex(process.argv[2])
  const require = createRequire(import.meta.url)
  const binding = require(indexPath)
  const binaryPath =
    process.env.PARATIX_SSH_NATIVE_PATH ??
    join(dirname(indexPath), `ssh-native.${binding.currentTarget()}.node`)
  const binarySha256 = createHash("sha256").update(readFileSync(binaryPath)).digest("hex")

  const ssh2 = requireSsh2()
  const { privateKey: clientKeyPem, publicKey: clientPublicKey } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  })
  const clientPublic = createPublicKey(clientPublicKey)
  const { server, state, hostKeyBase64 } = startServer(ssh2, clientPublic)
  await new Promise((r) => server.listen(0, "127.0.0.1", r))
  const port = server.address().port

  const keyDir = mkdtempSync(join(tmpdir(), "paratix-smoke-"))
  const keyPath = join(keyDir, "client_ed25519.pem")
  writeFileSync(keyPath, clientKeyPem, { mode: 0o600 })
  const childEnv = {
    ...process.env,
    SMOKE_INDEX: indexPath,
    SMOKE_PORT: String(port),
    SMOKE_KEY: keyPath,
    SMOKE_HOST_KEY: hostKeyBase64,
  }

  const checks = {}
  const check = async (name, fn) => {
    try {
      checks[name] = { status: "pass", ...(await fn()) }
    } catch (error) {
      checks[name] = { status: "fail", error: error?.message ?? String(error), code: error?.code }
    }
  }

  try {
    await check("scan", async () => {
      const info = await binding.scan({ host: "127.0.0.1", port, timeoutMs: 10_000 })
      if (info.keyBase64 !== hostKeyBase64) throw new Error("scan returned a different host key")
      return { algorithm: info.algorithm, fingerprint: info.fingerprintSha256 }
    })
    await check("keyLoginAndExec", async () => {
      const key = Buffer.from(clientKeyPem)
      const session = await binding.connect(
        { host: "127.0.0.1", port, user: "smoke", privateKey: key },
        async (info) => info.keyBase64 === hostKeyBase64
      )
      try {
        if (!state.signatureVerified) throw new Error("server did not verify the ed25519 signature")
        if (!key.every((b) => b === 0)) throw new Error("key buffer was not zero-filled")
        const channel = await session.exec("exit 7")
        channel.stdin.end()
        const chunks = []
        channel.stdout.on("data", (d) => chunks.push(d))
        const result = await channel.done
        const stdout = Buffer.concat(chunks).toString()
        if (result.code !== 7 || stdout !== "smoke exec\n") {
          throw new Error(`exec returned code ${result.code}, stdout ${JSON.stringify(stdout)}`)
        }
        return { authInfo: session.authInfo, execCode: result.code }
      } finally {
        await session.close()
      }
    })
    await check("panicToInternal", async () => {
      const result = await runChild("panic", childEnv, "PANIC")
      const line = result.stdout.split("\n").find((l) => l.startsWith("PANIC "))
      const outcome = line ? JSON.parse(line.slice(6, line.lastIndexOf(" "))) : null
      if (result.code !== 0 || result.stderr !== "" || outcome?.code !== "INTERNAL") {
        throw new Error(
          `panic probe: ${JSON.stringify({ code: result.code, stderr: result.stderr, outcome })}`
        )
      }
      return { code: outcome.code, stderrEmpty: true }
    })
    await check("destroyExitIdle", () => destroyExitRuns("destroy-exit-sleep", childEnv))
    await check("destroyExitStreaming", () => destroyExitRuns("destroy-exit-stream", childEnv))
  } finally {
    server.close()
  }

  const ok = Object.values(checks).every((c) => c.status === "pass")
  console.log(
    JSON.stringify({
      smoke: ok ? "pass" : "fail",
      platform: `${process.platform}-${process.arch}`,
      node: process.version,
      binding: indexPath,
      binary: binaryPath,
      binarySha256,
      target: binding.currentTarget(),
      cryptoBackend: binding.cryptoBackend(),
      checks,
    })
  )
  process.exitCode = ok ? 0 : 1
}

main().catch((error) => {
  console.error(`smoke: fail: ${error?.message ?? error}`)
  process.exitCode = 1
})
