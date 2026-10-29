// THROWAWAY SPIKE (issue #254): per-target prebuild smoke test.
//
//   node smoke.mjs                      # loads ../index.js (current platform)
//   node smoke.mjs ./ssh-native.linux-x64-musl.node   # loads a given binary
//   node smoke.mjs ./dir-with-index-js  # loads <dir>/index.js
//
// Needs only `ssh2` resolvable from this file or the working directory.
// Starts an in-process ssh2 Server, runs scan(), checks the key, exits 0/1.
import { generateKeyPairSync } from "node:crypto"
import { existsSync, statSync } from "node:fs"
import { createRequire } from "node:module"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const here = dirname(fileURLToPath(import.meta.url))

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

function loadBinding(arg) {
  const require = createRequire(import.meta.url)
  if (arg && arg.endsWith(".node")) {
    const raw = require(resolve(arg))
    // Raw binding: errors stay in the native `CODE|detail|message` form.
    return {
      scan: (o) => raw.scan(o),
      cryptoBackend: () => raw.cryptoBackend(),
      source: resolve(arg),
    }
  }
  const dir = arg ? resolve(arg) : join(here, "..")
  const index = existsSync(dir) && statSync(dir).isDirectory() ? join(dir, "index.js") : dir
  const binding = require(index)
  return {
    scan: binding.scan,
    cryptoBackend: binding.cryptoBackend,
    source: index,
    target: binding.currentTarget?.(),
  }
}

async function main() {
  const binding = loadBinding(process.argv[2])
  const { Server, utils } = requireSsh2()
  // RSA PKCS#1 host key, as in startTestSshServer (cli.dist.test.ts).
  const { privateKey: hostKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { format: "pem", type: "pkcs1" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  })
  const expected = utils.parseKey(hostKey).getPublicSSH().toString("base64")
  const server = new Server({ hostKeys: [hostKey] }, (client) => {
    client.on("error", () => {})
    client.on("authentication", (ctx) => ctx.reject())
  })
  await new Promise((r) => server.listen(0, "127.0.0.1", r))
  try {
    const info = await binding.scan({
      host: "127.0.0.1",
      port: server.address().port,
      timeoutMs: 10_000,
    })
    const ok = info.keyBase64 === expected
    console.log(
      JSON.stringify({
        smoke: ok ? "pass" : "fail",
        platform: `${process.platform}-${process.arch}`,
        node: process.version,
        binding: binding.source,
        target: binding.target,
        cryptoBackend: binding.cryptoBackend(),
        algorithm: info.algorithm,
        fingerprint: info.fingerprintSha256,
      })
    )
    process.exitCode = ok ? 0 : 1
  } finally {
    server.close()
  }
}

main().catch((error) => {
  console.error(`smoke: fail: ${error?.message ?? error}`)
  process.exitCode = 1
})
