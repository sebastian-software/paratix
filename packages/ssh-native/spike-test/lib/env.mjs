// THROWAWAY SPIKE (issue #254): target selection and shared helpers.
//
// Docker/remote target (CI): set SPIKE_SSH_HOST and SPIKE_FIXTURE_DIR, plus
// optionally SPIKE_SSH_PORT (22 profile, default 2222), SPIKE_SSH_PORT_MAXSESSIONS
// (default 2223), SPIKE_SSH_PORT_PASSWORD (2224), SPIKE_SSH_PORT_KBDINT (2225),
// SPIKE_SSH_USER (paratix), SPIKE_SSH_PASSWORD (paratix-spike-password).
// Local target (default): fixtures are generated once and a non-root sshd is spawned.
import { execFileSync, spawn } from "node:child_process"
import { existsSync, mkdtempSync, readFileSync } from "node:fs"
import { createRequire } from "node:module"
import { tmpdir, userInfo } from "node:os"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

import { startLocalSshd } from "../local-sshd.mjs"

const here = dirname(fileURLToPath(import.meta.url))
export const PACKAGE_DIR = join(here, "..", "..")
const require = createRequire(import.meta.url)

export const TARGET = process.env.SPIKE_SSH_HOST ? (process.env.SPIKE_TARGET ?? "docker") : "local"
export const native = require(join(PACKAGE_DIR, "index.js"))

export function ensureFixtures() {
  const dir =
    process.env.SPIKE_FIXTURE_DIR ?? join(tmpdir(), `paratix-spike-fixtures-${userInfo().username}`)
  if (!existsSync(join(dir, "manifest.json"))) {
    if (TARGET !== "local") throw new Error(`SPIKE_FIXTURE_DIR ${dir} has no manifest.json`)
    execFileSync("bash", [join(PACKAGE_DIR, "spike-fixture", "generate.sh"), dir], {
      env: { ...process.env, SPIKE_CERT_PRINCIPALS: `paratix,${userInfo().username}` },
      stdio: "ignore",
    })
  }
  return dir
}

/**
 * @returns {Promise<{ host: string, port: number, maxSessionsPort: number,
 *   passwordPort: number|null, kbdintPort: number|null, user: string,
 *   password: string|null, fixtureDir: string, stop(): Promise<void> }>}
 */
export async function setupTarget() {
  const fixtureDir = ensureFixtures()
  if (TARGET === "local") {
    const sshd = await startLocalSshd({ fixtureDir })
    return {
      host: "127.0.0.1",
      port: sshd.port,
      maxSessionsPort: sshd.maxSessionsPort,
      passwordPort: null,
      kbdintPort: null,
      user: userInfo().username,
      password: null,
      fixtureDir,
      stop: () => sshd.stop(),
    }
  }
  const env = process.env
  return {
    host: env.SPIKE_SSH_HOST,
    port: Number(env.SPIKE_SSH_PORT ?? 2222),
    maxSessionsPort: Number(env.SPIKE_SSH_PORT_MAXSESSIONS ?? 2223),
    passwordPort: Number(env.SPIKE_SSH_PORT_PASSWORD ?? 2224),
    kbdintPort: Number(env.SPIKE_SSH_PORT_KBDINT ?? 2225),
    user: env.SPIKE_SSH_USER ?? "paratix",
    password: env.SPIKE_SSH_PASSWORD ?? "paratix-spike-password",
    fixtureDir,
    stop: async () => {},
  }
}

export function readFixture(fixtureDir, name) {
  return readFileSync(join(fixtureDir, name))
}

/** Second field of an OpenSSH public key line. */
export function publicKeyBase64(fixtureDir, name) {
  return readFileSync(join(fixtureDir, name), "utf8").trim().split(/\s+/)[1]
}

/** Host key verifier that pins the fixture host keys (any of them). */
export function pinnedVerifier(fixtureDir, seen = []) {
  const allowed = new Set(
    ["host_ed25519.pub", "host_ecdsa.pub", "host_rsa.pub"].map((f) =>
      publicKeyBase64(fixtureDir, f)
    )
  )
  return async (info) => {
    seen.push(info)
    if (info.kind !== "key") return false
    return allowed.has(info.keyBase64)
  }
}

/**
 * Starts a private ssh-agent and adds the given fixture keys.
 * `ssh-add <key>` also loads `<key>-cert.pub` when it exists.
 */
export async function startAgent(fixtureDir, keys) {
  const dir = mkdtempSync(join(tmpdir(), "paratix-spike-agent-"))
  const socket = join(dir, "agent.sock")
  const child = spawn("ssh-agent", ["-D", "-a", socket], { stdio: "ignore" })
  const deadline = Date.now() + 5000
  while (!existsSync(socket)) {
    if (Date.now() > deadline) throw new Error("ssh-agent did not create its socket")
    await new Promise((r) => setTimeout(r, 20))
  }
  const results = {}
  for (const key of keys) {
    try {
      execFileSync("ssh-add", [resolve(fixtureDir, key)], {
        env: { ...process.env, SSH_AUTH_SOCK: socket },
        stdio: ["ignore", "ignore", "pipe"],
      })
      results[key] = "added"
    } catch (error) {
      results[key] = `ssh-add failed: ${String(error.stderr ?? error.message).trim()}`
    }
  }
  const listing = (() => {
    try {
      return execFileSync("ssh-add", ["-L"], {
        env: { ...process.env, SSH_AUTH_SOCK: socket },
      }).toString()
    } catch {
      return ""
    }
  })()
  return {
    socket,
    added: results,
    listing,
    stop: async () => {
      child.kill("SIGTERM")
    },
  }
}

export async function readAll(stream) {
  const chunks = []
  for await (const chunk of stream) chunks.push(chunk)
  return Buffer.concat(chunks)
}

/** Runs a command to completion and collects its output. */
export async function run(session, command, stdin) {
  const channel = await session.exec(command)
  const outP = readAll(channel.stdout)
  const errP = readAll(channel.stderr)
  if (stdin !== undefined) channel.stdin.end(stdin)
  else channel.stdin.end()
  const [stdout, stderr, result] = await Promise.all([outP, errP, channel.done])
  return { ...result, stdout: stdout.toString(), stderr: stderr.toString() }
}

export async function connectWithKey(target, keyName = "key_ed25519_openssh", extra = {}) {
  return await native.connect(
    {
      host: target.host,
      port: extra.port ?? target.port,
      user: target.user,
      privateKey: readFixture(target.fixtureDir, keyName),
      ...extra,
    },
    pinnedVerifier(target.fixtureDir)
  )
}
