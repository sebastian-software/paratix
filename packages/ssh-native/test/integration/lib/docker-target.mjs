// Docker target: builds the image from test/integration/fixture (no per-run
// key material in it), creates one container with every sshd profile on
// random 127.0.0.1 ports, copies the per-run host key, user CA and
// authorized_keys into it before it starts, and removes container and image
// again.
import { execFile } from "node:child_process"
import { randomBytes, randomUUID } from "node:crypto"
import { join } from "node:path"

import { waitForBanners } from "./net.mjs"
import { runTool } from "./tools.mjs"

const FIXTURE_DIR = join(import.meta.dirname, "..", "fixture")
const LABEL_PREFIX = "com.sebastian-software.paratix.ssh-native-integration"
const PROFILE_PORTS = { keyboardInteractive: 2225, main: 2222, password: 2224, userCa: 2223 }
// The full-file-system test writes more than this into the tmpfs.
export const FULL_FS_PATH = "/mnt/full"
const FULL_FS_SIZE = "1m"
const BUILD_TIMEOUT_MS = 600_000
const READY_TIMEOUT_MS = 30_000
const DIAGNOSTICS_TIMEOUT_MS = 10_000
const LOG_TAIL_LINES = "50"
const USER = "paratix"
const KEY_DIR = "/etc/ssh/ssh-native-it"
const AUTHORIZED_KEYS = `/home/${USER}/.ssh/authorized_keys`

/**
 * @typedef {object} Resources
 * @property {string[]} labels `--label` arguments
 * @property {string} name container name
 * @property {string} tag image tag
 */

/**
 * @typedef {object} StartOptions
 * @property {(cleanup: () => Promise<void>) => void} defer registers a
 *   cleanup with the runner before the resource it removes is created
 */

/** Swallows a settled step's outcome; the guard only waits for it. */
function ignore() {
  // Nothing to do.
}

/**
 * Serializes the start steps for a teardown that may arrive at any time:
 * `halt()` aborts the running step if it supports a signal (the build),
 * waits until it settled, and makes every later step fail, so no resource
 * is created after the cleanup ran.
 *
 * @returns `run()` and `halt()`
 */
function stepGuard() {
  const controller = new AbortController()
  /** @type {Promise<unknown>} */
  let pending = Promise.resolve()
  return {
    async halt() {
      controller.abort()
      await pending
    },
    /**
     * @param step one start step; gets the teardown's abort signal
     * @returns the step's result
     */
    run(step) {
      if (controller.signal.aborted) {
        return Promise.reject(new Error("the Docker target is being torn down"))
      }
      const result = step(controller.signal)
      pending = result.then(ignore, ignore)
      return result
    },
  }
}

/**
 * @param name container name
 * @param port container port
 * @returns the published 127.0.0.1 port
 */
async function publishedPort(name, port) {
  const output = await runTool("docker", ["port", name, `${port}/tcp`])
  const match = /:(?<port>\d+)\s*$/mv.exec(output.trim().split("\n")[0])
  if (!match?.groups) throw new Error(`unexpected docker port output: ${output}`)
  return Number(match.groups.port)
}

/**
 * @param name container name
 * @returns every profile's published port
 */
async function readPorts(name) {
  const entries = await Promise.all(
    Object.entries(PROFILE_PORTS).map(async ([profile, port]) => [
      profile,
      await publishedPort(name, port),
    ])
  )
  return /** @type {Record<keyof typeof PROFILE_PORTS, number>} */ (Object.fromEntries(entries))
}

/**
 * @param resources container name and image tag
 * @returns removes both, best effort
 */
function removeResources(resources) {
  return async () => {
    await runTool("docker", ["rm", "-f", resources.name]).catch(() => "")
    await runTool("docker", ["image", "rm", "-f", resources.tag]).catch(() => "")
  }
}

/**
 * @param resources container name, image tag and labels
 * @returns resolves once the container exists (not started)
 */
async function createContainer(resources) {
  const publish = Object.values(PROFILE_PORTS).flatMap((port) => [
    "--publish",
    `127.0.0.1::${port}`,
  ])
  const tmpfs = `${FULL_FS_PATH}:rw,size=${FULL_FS_SIZE},mode=1777`
  await runTool("docker", [
    "create",
    "--name",
    resources.name,
    ...resources.labels,
    "--tmpfs",
    tmpfs,
    ...publish,
    resources.tag,
  ])
}

/**
 * Copies the per-run keys into the created container; its start command
 * (fixture/start.sh) sets ownership and modes and runs `sshd -t`.
 *
 * @param name container name
 * @param fixtures the generated fixtures
 */
async function copyKeys(name, fixtures) {
  const copies = [
    [fixtures.hostKey, `${KEY_DIR}/host_ed25519`],
    [fixtures.userCaPublic, `${KEY_DIR}/user_ca.pub`],
    [fixtures.authorizedKeys, AUTHORIZED_KEYS],
  ]
  for (const [source, destination] of copies) {
    // eslint-disable-next-line no-await-in-loop -- one docker cp at a time
    await runTool("docker", ["cp", source, `${name}:${destination}`])
  }
}

/**
 * Runs a diagnostic docker command; never rejects.
 *
 * @param args docker arguments
 * @returns stdout and stderr (sshd and start.sh log to stderr), or `""`
 */
function dockerOutput(args) {
  return new Promise((resolve) => {
    try {
      execFile(
        "docker",
        args,
        { encoding: "utf8", timeout: DIAGNOSTICS_TIMEOUT_MS },
        (_error, stdout, stderr) => resolve(`${stdout ?? ""}${stderr ?? ""}`.trim())
      )
    } catch {
      resolve("")
    }
  })
}

/**
 * Best-effort container state and log tail for a failed start. The log
 * holds sshd and start.sh output only; no key material is ever printed.
 *
 * @param name the container to inspect
 * @returns diagnostic text, never throws
 */
async function containerDiagnostics(name) {
  const [state, logs] = await Promise.all([
    dockerOutput(["inspect", "-f", "{{.State.Status}}, exit code {{.State.ExitCode}}", name]),
    dockerOutput(["logs", "--tail", LOG_TAIL_LINES, name]),
  ])
  return `container state: ${state || "unknown"}; last ${LOG_TAIL_LINES} log lines:\n${logs || "(none)"}`
}

/**
 * Reads the published ports and waits until sshd greets on every one. If
 * start.sh failed (ownership, modes, `sshd -t`) the container has already
 * exited and `docker port` fails; either way the error carries the
 * container state and log.
 *
 * @param name container name
 * @param signal ends the wait on teardown
 * @returns every profile's published port
 */
async function readyPorts(name, signal) {
  try {
    const ports = await readPorts(name)
    await waitForBanners(Object.values(ports), READY_TIMEOUT_MS, { signal })
    return ports
  } catch (error) {
    // Torn down on purpose: no diagnostics for a container being removed.
    if (signal.aborted) throw error
    const diagnostics = await containerDiagnostics(name)
    const reason = error instanceof Error ? error.message : String(error)
    throw new Error(`the sshd container did not become ready: ${reason}\n${diagnostics}`, {
      cause: error,
    })
  }
}

/**
 * Sets a per-run password for `paratix` through stdin, so it appears in
 * neither the image, its history, the environment nor a command line.
 *
 * @param name container name
 * @returns the generated password, for the PAM login tests
 */
async function setPassword(name) {
  const password = randomBytes(18).toString("base64url")
  await runTool("docker", ["exec", "-i", name, "chpasswd"], { input: `${USER}:${password}\n` })
  return password
}

/** @returns per-run container name, image tag and labels */
function newResources() {
  const id = randomUUID()
  /** @type {Resources} */
  const resources = {
    labels: [`${LABEL_PREFIX}.managed=true`, `${LABEL_PREFIX}.id=${id}`].flatMap((label) => [
      "--label",
      label,
    ]),
    name: `paratix-ssh-native-it-${id}`,
    tag: `paratix-ssh-native-it-sshd:${id}`,
  }
  return resources
}

/**
 * Builds and starts the container. Its cleanup is registered through
 * `defer` before the first resource exists; a failed start leaves the
 * removal to the runner's teardown.
 *
 * @param fixtures fixtures generated for the user `paratix`
 * @param options the runner's cleanup registration (StartOptions)
 * @returns the target description
 */
export async function startDockerTarget(fixtures, options) {
  const { defer } = /** @type {StartOptions} */ (options)
  const resources = newResources()
  const steps = stepGuard()
  const remove = removeResources(resources)
  defer(async () => {
    await steps.halt()
    await remove()
  })
  const { name, tag } = resources
  const build = ["build", ...resources.labels, "-t", tag, FIXTURE_DIR]
  await steps.run((signal) => runTool("docker", build, { signal, timeoutMs: BUILD_TIMEOUT_MS }))
  await steps.run(() => createContainer(resources))
  await steps.run(() => copyKeys(name, fixtures))
  await steps.run(() => runTool("docker", ["start", name]))
  const ports = await steps.run((signal) => readyPorts(name, signal))
  const password = await steps.run(() => setPassword(name))
  return {
    container: name,
    features: { pam: true, tmpfs: true },
    host: "127.0.0.1",
    kind: "docker",
    password,
    ports,
    user: USER,
  }
}

export const DOCKER_USER = USER
