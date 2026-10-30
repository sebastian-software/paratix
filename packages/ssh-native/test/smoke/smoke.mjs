// Smoke test of the binary the loader picks on this machine.
//
//   node packages/ssh-native/test/smoke/smoke.mjs
//
// Plain `node` only: no pnpm, Docker or sshd. `ssh2` resolves through the
// workspace node_modules, so it also runs in ubuntu:22.04 and
// node:24-alpine containers with the repository bind-mounted. Against an
// in-process ssh2 server (test/helpers/server.mjs) it checks scan(), an
// ed25519 key login (the server verifies the signature; the caller's key
// buffer is zero-filled), exec with exit code 7, the panic probe ending as
// INTERNAL with an empty stderr (child process), and 20 runs each of
// destroy() + process.exit(0) on an idle connection and during streaming
// output (child processes: exit code 0, no signal, empty stderr).
//
// The first line names the binary actually loaded:
//   ssh-native smoke: target=<target> sha256=<hex> path=<abs path>
// With SSH_NATIVE_EXPECTED_SHA256 set, that hash must match. Exit code 1
// on any failure.
import { spawnSync } from "node:child_process"
import { createHash } from "node:crypto"
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { createRequire } from "node:module"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { fileURLToPath } from "node:url"

import { childEnvironment, exitWithin, startChild } from "../helpers/lifecycle.mjs"
import { clientKey, startServer, TEST_USER } from "../helpers/server.mjs"

const require = createRequire(import.meta.url)
const PANIC_CHILD = fileURLToPath(new URL("../children/panic-child.mjs", import.meta.url))
const INTERNAL_MESSAGE = "internal error in the native SSH binding"
const RUNS = 20
const EXIT_WAIT_MS = 5000
const STREAM_COMMAND = `stdout-flood ${1024 * 1024 * 1024}`

/** @type {typeof import("../../index.js")} */
const binding = require("../../index.js")

/** @returns absolute path of the native binary the loader loaded */
function loadedBinary() {
  const path = Object.keys(require.cache).find((file) => /ssh-native[^\/\\]*\.node$/v.test(file))
  if (!path) throw new Error("the loaded native binary is not in the module cache")
  return path
}

/**
 * @param context server, key and child environment
 * @returns details for the report
 */
async function checkScan(context) {
  const info = await binding.scan({ host: "127.0.0.1", port: context.server.port })
  if (info.keyBase64 !== context.server.hostKeyBase64) throw new Error("scan saw another host key")
  return `${info.algorithm} ${info.fingerprintSha256}`
}

/**
 * @param context server, key and child environment
 * @returns details for the report
 */
async function checkLoginAndExec(context) {
  const privateKey = Buffer.from(context.key.privateKey)
  const { hostKeyBase64, port } = context.server
  const session = await binding.connect(
    { host: "127.0.0.1", port, privateKey, user: TEST_USER },
    (info) => info.keyBase64 === hostKeyBase64
  )
  try {
    if (!privateKey.every((byte) => byte === 0)) throw new Error("key buffer not zero-filled")
    const channel = await session.exec("exit 7")
    channel.stdout.resume()
    channel.stderr.resume()
    const exit = await channel.exit
    if (exit.code !== 7) throw new Error(`exec exit ${JSON.stringify(exit)}`)
    return `${session.authInfo.method} ${session.authInfo.algorithm}, exec exit ${exit.code}`
  } finally {
    await session.close()
  }
}

/** @returns details for the report */
function checkPanic() {
  const child = spawnSync(process.execPath, [PANIC_CHILD], { encoding: "utf8", timeout: 30_000 })
  const lines = child.stdout.trim().split("\n")
  const outcomes = lines.slice(0, -1).map((line) => JSON.parse(line))
  const allInternal = outcomes.every(
    (outcome) => outcome.code === "INTERNAL" && outcome.message === INTERNAL_MESSAGE
  )
  const clean = child.status === 0 && child.signal === null && child.stderr === ""
  if (!clean || lines.at(-1) !== "PROBES-DONE" || outcomes.length !== 6 || !allInternal) {
    throw new Error(`panic probe: status ${child.status}, stderr ${JSON.stringify(child.stderr)}`)
  }
  return `${outcomes.length} kinds INTERNAL, stderr empty`
}

/**
 * Runs the destroy() + process.exit(0) child RUNS times.
 *
 * @param mode lifecycle-child mode
 * @param env child environment
 * @returns details for the report
 */
async function destroyExitRuns(mode, env) {
  let maxLatency = 0
  for (let index = 0; index < RUNS; index += 1) {
    // eslint-disable-next-line no-await-in-loop -- one child at a time
    const handle = await startChild(mode, env, "READY")
    // eslint-disable-next-line no-await-in-loop -- one child at a time
    const exit = await exitWithin(handle, EXIT_WAIT_MS)
    if (exit === null) handle.kill()
    if (!exit || exit.code !== 0 || exit.signal !== null || handle.stderr() !== "") {
      throw new Error(`run ${index}: ${JSON.stringify(exit)} ${handle.stderr()}`)
    }
    maxLatency = Math.max(maxLatency, exit.at - handle.markerAt)
  }
  return `${RUNS} runs, exit code 0, no signal, empty stderr, max exit latency ${maxLatency} ms`
}

/**
 * @param name check name
 * @param run the check
 * @returns whether it passed; prints one result line
 */
async function report(name, run) {
  try {
    console.log(`PASS ${name}: ${await run()}`)
    return true
  } catch (error) {
    console.log(`FAIL ${name}: ${error instanceof Error ? error.message : String(error)}`)
    return false
  }
}

/**
 * @param context server, key and child environments
 * @returns whether every check passed
 */
async function runChecks(context) {
  const results = [
    await report("scan", () => checkScan(context)),
    await report("ed25519 login and exec", () => checkLoginAndExec(context)),
    await report("panic probe", checkPanic),
    await report("destroy + exit, idle", () => destroyExitRuns("destroy-exit", context.idleEnv)),
    await report("destroy + exit, streaming", () =>
      destroyExitRuns("destroy-exit-streaming", context.streamEnv)
    ),
  ]
  return results.every(Boolean)
}

/**
 * Starts the in-process server and writes the client key for the children.
 *
 * @param use runs the checks against the server
 * @returns what `use` returned
 */
async function withServer(use) {
  const key = clientKey()
  const server = await startServer({ keys: [key.publicKey] })
  const dir = mkdtempSync(join(tmpdir(), "ssh-native-smoke-"))
  try {
    const keyPath = join(dir, "client_ed25519")
    writeFileSync(keyPath, key.privateKey, { mode: 0o600 })
    const { host, hostKeyBase64, port } = server
    const connection = { host, hostKeyBase64, keyPath, port, user: TEST_USER }
    return await use({
      idleEnv: childEnvironment(connection, { SSH_NATIVE_CHILD_COMMAND: "sleep" }),
      key,
      server,
      streamEnv: childEnvironment(connection, { SSH_NATIVE_CHILD_COMMAND: STREAM_COMMAND }),
    })
  } finally {
    await server.close()
    rmSync(dir, { force: true, recursive: true })
  }
}

/** @returns the process exit code */
async function main() {
  const path = loadedBinary()
  const sha256 = createHash("sha256").update(readFileSync(path)).digest("hex")
  console.log(`ssh-native smoke: target=${binding.currentTarget()} sha256=${sha256} path=${path}`)
  const expected = process.env.SSH_NATIVE_EXPECTED_SHA256
  if (expected && expected.trim().toLowerCase() !== sha256) {
    console.log(`FAIL expected sha256: SSH_NATIVE_EXPECTED_SHA256 is ${expected.trim()}`)
    return 1
  }
  return (await withServer(runChecks)) ? 0 : 1
}

try {
  process.exitCode = await main()
} catch (error) {
  console.log(`FAIL smoke: ${error instanceof Error ? error.message : String(error)}`)
  process.exitCode = 1
}
