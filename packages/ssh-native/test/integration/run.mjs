// Runner of the @paratix/ssh-native integration suite.
//
//   node test/integration/run.mjs docker [node --test options]   (test:integration)
//   node test/integration/run.mjs local  [node --test options]   (test:integration:local)
//
// It generates keys, CA and certificates into a private temp directory,
// starts the target once (a Docker container with every sshd profile, or a
// non-root local sshd), runs every `*.test.mjs` file here with
// `node --test --test-concurrency=1` and always tears the target down.
// Every resource registers its cleanup before (or as) it is created, so a
// SIGINT/SIGTERM at any point, also during startup, stops the tests (their
// whole process group), leftover agents and remote sleeps, the target, and
// removes the run directory before the runner exits. After a signal no
// further start step begins, and a cleanup registered by a step that was
// already running runs at once; the teardown waits for the startup to stop
// and drains every registered cleanup.
//
// Without Docker (or without sshd, ssh-keygen, ssh-agent, ssh-add) the tests
// that need the target are skipped with the reason; with CI=true the run
// fails instead. With CI=true every hard proof (lib/proofs.mjs) must pass.
import { spawn } from "node:child_process"
import { once } from "node:events"
import { mkdir, mkdtemp, readdir, readFile, realpath, rm, writeFile } from "node:fs/promises"
import { tmpdir, userInfo } from "node:os"
import { join } from "node:path"

import { DOCKER_USER, startDockerTarget } from "./lib/docker-target.mjs"
import { generateFixtures } from "./lib/keys.mjs"
import { LOCAL_SSHD, startLocalTarget } from "./lib/local-target.mjs"
import { DESCRIPTOR_ENV, HARD_PROOFS, isCi, RESULTS_ENV } from "./lib/proofs.mjs"
import { hasTool, isDockerReachable, missingTools, runTool } from "./lib/tools.mjs"

const HERE = import.meta.dirname
const KEY_TOOLS = ["ssh-keygen", "ssh-agent", "ssh-add"]
const SIGNAL_EXIT_CODE = 130
const TEST_STOP_TIMEOUT_MS = 5000
const INTERRUPTED = "interrupted by a signal, startup stopped"

/**
 * @typedef {object} Run
 * @property {string} dir private run directory
 * @property {string} marker run marker for remote sleep commands
 * @property {(() => Promise<void>)[]} cleanups registered cleanups, run last first
 * @property {Set<Promise<void>>} lateCleanups cleanups registered after a
 *   signal, already running
 * @property {Promise<unknown>} startup fixtures and target start; settles
 *   soon after a signal because every start step checks `interrupted()`
 * @property {Set<import("node:child_process").ChildProcess>} tests the started `node --test` process
 * @property {() => boolean} interrupted whether a SIGINT/SIGTERM started the teardown
 */

/** Swallows a settled promise's outcome; the teardown only waits for it. */
function ignore() {
  // Nothing to do.
}

/**
 * Stops the startup before its next step once a signal arrived.
 *
 * @param run knows whether a SIGINT/SIGTERM arrived
 */
function throwIfInterrupted(run) {
  if (run.interrupted()) throw new Error(INTERRUPTED)
}

/**
 * @param cleanup a registered cleanup
 * @returns resolves once it ran; a failure is reported, never thrown
 */
async function runCleanup(cleanup) {
  try {
    await cleanup()
  } catch (error) {
    console.error(`ssh-native integration: cleanup failed: ${error?.message ?? error}`)
  }
}

/**
 * @param kind `docker` or `local`
 * @returns why the target cannot run here, or `null`
 */
function unavailableReason(kind) {
  const tools = missingTools(KEY_TOOLS)
  if (tools) return tools
  if (kind === "docker") {
    return isDockerReachable() ? null : "no reachable Docker daemon (`docker info` failed)"
  }
  return hasTool(LOCAL_SSHD) ? null : `missing sshd at ${LOCAL_SSHD} (set SSH_NATIVE_IT_SSHD)`
}

/**
 * Generates the fixtures and starts the target; the target registers its
 * cleanup in `run.cleanups` before it creates anything.
 *
 * @param kind `docker` or `local`
 * @param run directory, marker, registered cleanups and test process
 * @returns descriptor fields
 */
async function startTarget(kind, run) {
  const fixtureDir = join(run.dir, "fixtures")
  throwIfInterrupted(run)
  await mkdir(fixtureDir, { mode: 0o700 })
  const principal = kind === "docker" ? DOCKER_USER : userInfo().username
  throwIfInterrupted(run)
  const fixtures = await generateFixtures(fixtureDir, principal)
  // After a signal the teardown may already have drained `run.cleanups`:
  // run a late cleanup at once and stop the start step that registered it.
  const defer = (/** @type {() => Promise<void>} */ cleanup) => {
    if (run.interrupted()) {
      run.lateCleanups.add(runCleanup(cleanup))
      throw new Error(INTERRUPTED)
    }
    run.cleanups.push(cleanup)
  }
  throwIfInterrupted(run)
  const target =
    kind === "docker"
      ? await startDockerTarget(fixtures, { defer })
      : await startLocalTarget(fixtures, { defer, runDir: run.dir })
  return { fixtures, target }
}

/**
 * Runs the tests in their own process group, so the teardown can stop the
 * test files and everything they spawned (ssh-agent) at once.
 *
 * @param args extra `node --test` options
 * @param env environment of the test processes
 * @param run records the test process for the teardown
 * @returns the exit code of `node --test`
 */
async function runTests(args, env, run) {
  const entries = await readdir(HERE)
  const files = entries.filter((file) => file.endsWith(".test.mjs")).sort()
  // The teardown stops only test processes it can see: start none after a signal.
  throwIfInterrupted(run)
  const child = spawn(
    process.execPath,
    ["--test", "--test-concurrency=1", ...args, ...files.map((file) => join(HERE, file))],
    { detached: process.platform !== "win32", env, stdio: "inherit" }
  )
  run.tests.add(child)
  const [code, signal] = await once(child, "exit")
  return signal ? 1 : Number(code)
}

/**
 * @param child the test process
 * @param signal the signal for it and its process group
 */
function signalTests(child, signal) {
  try {
    if (process.platform === "win32" || child.pid === undefined) child.kill(signal)
    else process.kill(-child.pid, signal)
  } catch {
    // The process group is already gone.
  }
}

/**
 * Stops a still running `node --test` and its process group: SIGTERM,
 * SIGKILL after TEST_STOP_TIMEOUT_MS, then SIGKILL for stragglers.
 *
 * @param child the test process
 */
async function stopTests(child) {
  if (child.exitCode !== null || child.signalCode !== null) return
  const exited = once(child, "exit")
  signalTests(child, "SIGTERM")
  const timer = setTimeout(() => signalTests(child, "SIGKILL"), TEST_STOP_TIMEOUT_MS)
  await exited
  clearTimeout(timer)
  signalTests(child, "SIGKILL")
}

/**
 * @param resultsPath the results file
 * @returns hard proofs without a pass record
 */
async function missingHardProofs(resultsPath) {
  const text = await readFile(resultsPath, "utf8").catch(() => "")
  const passed = new Set(text.split("\n").map((line) => line.replace(/^pass /v, "")))
  return HARD_PROOFS.filter((id) => !passed.has(id))
}

/**
 * Prints the hard-proof summary; with CI=true a missing proof fails the run.
 *
 * @param resultsPath the results file
 * @returns whether the gate passed
 */
async function hardProofGate(resultsPath) {
  const missing = await missingHardProofs(resultsPath)
  const passed = HARD_PROOFS.length - missing.length
  console.log(`ssh-native integration: ${passed}/${HARD_PROOFS.length} hard proofs passed`)
  if (missing.length === 0) return true
  console.log(`ssh-native integration: hard proofs not passed: ${missing.join(", ")}`)
  return !isCi()
}

/**
 * @param text literal text (a temp directory path)
 * @returns the text as a `pkill -f` regular expression; every character
 *   other than a word character, `/` or `-` becomes a bracket expression
 */
function escapeRegExp(text) {
  return [...text].map((char) => (/[\w\/\-]/v.test(char) ? char : `[${char}]`)).join("")
}

/**
 * Kills what a run may leave behind: ssh-agents of the test files (their
 * sockets live in the run directory) and, for a local run, remote commands
 * (exec runs without a PTY, so `destroy()` does not stop them; they all
 * carry the run marker).
 *
 * @param kind `docker` or `local`
 * @param run directory, marker, registered cleanups and test process
 */
async function killLeftovers(kind, run) {
  const agents = `^ssh-agent -D -a ${escapeRegExp(run.dir)}/`
  await runTool("pkill", ["-f", agents]).catch(() => "")
  if (kind !== "local") return
  await runTool("pkill", ["-f", `^sleep [0-9]+\\.${run.marker}$`]).catch(() => "")
}

/**
 * Runs the registered cleanups, last first, until none is left; one that a
 * cleanup or a still running start step registers meanwhile runs too.
 *
 * @param run registered cleanups
 */
async function drainCleanups(run) {
  let cleanup = run.cleanups.pop()
  while (cleanup) {
    // eslint-disable-next-line no-await-in-loop -- cleanups run in reverse order of creation
    await runCleanup(cleanup)
    cleanup = run.cleanups.pop()
  }
}

/**
 * Stops the tests, kills leftovers, runs the registered cleanups (last
 * first), waits for an interrupted startup to stop (its running step may
 * end only once a cleanup aborted it, e.g. the Docker build), drains what it
 * registered meanwhile, waits for the late cleanups and removes the run
 * directory.
 *
 * @param kind `docker` or `local`
 * @param run directory, marker, registered cleanups, startup and test process
 */
async function tearDown(kind, run) {
  await Promise.all([...run.tests].map((child) => stopTests(child)))
  await killLeftovers(kind, run)
  await drainCleanups(run)
  await run.startup.then(ignore, ignore)
  await drainCleanups(run)
  await Promise.all(run.lateCleanups)
  await rm(run.dir, { force: true, recursive: true })
}

/**
 * @param kind `docker` or `local`
 * @param run directory, marker, registered cleanups and test process
 * @returns the descriptor; a local skip if the target is unavailable
 */
async function prepare(kind, run) {
  const descriptor = {
    kind,
    marker: run.marker,
    runDir: run.dir,
    unavailable: unavailableReason(kind),
  }
  if (descriptor.unavailable === null) return { ...descriptor, ...(await startTarget(kind, run)) }
  if (isCi()) throw new Error(`${descriptor.unavailable}; with CI=true this fails the run`)
  console.log(`ssh-native integration: ${kind} target skipped: ${descriptor.unavailable}`)
  return descriptor
}

/**
 * Waits for the started target, runs the tests and applies the hard-proof
 * gate.
 *
 * @param run directory, marker, registered cleanups and test process
 * @param startup the running `prepare()`, also awaited by the teardown
 * @param testArgs extra `node --test` options
 * @returns the exit code
 */
async function runSuite(run, startup, testArgs) {
  const descriptor = await startup
  throwIfInterrupted(run)
  const descriptorPath = join(run.dir, "descriptor.json")
  await writeFile(descriptorPath, JSON.stringify(descriptor), { mode: 0o600 })
  const resultsPath = join(run.dir, "results.txt")
  const env = { ...process.env, [DESCRIPTOR_ENV]: descriptorPath, [RESULTS_ENV]: resultsPath }
  const code = await runTests(testArgs, env, run)
  // Tests stopped by a signal: no gate summary, the signal handler exits.
  if (run.interrupted()) return SIGNAL_EXIT_CODE
  return (await hardProofGate(resultsPath)) ? code : 1
}

/**
 * Runs the suite and always tears it down, also on SIGINT/SIGTERM at any
 * point; the teardown runs once even if a signal and the normal end meet.
 *
 * @returns the process exit code
 */
async function main() {
  const [kind = "docker", ...testArgs] = process.argv.slice(2)
  if (kind !== "docker" && kind !== "local") throw new Error(`unknown target ${kind}`)
  const dir = await realpath(await mkdtemp(join(await realpath(tmpdir()), "ssh-native-it-")))
  const marker = String(Date.now() % 1_000_000).padStart(6, "0")
  let interrupted = false
  /** @type {Run} */
  const run = {
    cleanups: [],
    dir,
    interrupted: () => interrupted,
    lateCleanups: new Set(),
    marker,
    startup: Promise.resolve(),
    tests: new Set(),
  }
  /** @type {Promise<void> | undefined} */
  let teardown
  const tearDownOnce = () => {
    teardown ??= tearDown(kind, run)
    return teardown
  }
  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => {
      interrupted = true
      console.error(`ssh-native integration: ${signal}, tearing down`)
      // eslint-disable-next-line node/no-process-exit -- end the run once everything is gone
      void tearDownOnce().finally(() => process.exit(SIGNAL_EXIT_CODE))
    })
  }
  try {
    const startup = prepare(kind, run)
    run.startup = startup
    return await runSuite(run, startup, testArgs)
  } finally {
    await tearDownOnce()
  }
}

try {
  process.exitCode = await main()
} catch (error) {
  console.error(`ssh-native integration: ${error instanceof Error ? error.message : error}`)
  process.exitCode = 1
}
