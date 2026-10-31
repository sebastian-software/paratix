// Parent side of the lifecycle proofs: spawns lifecycle-child.mjs, waits for
// its marker line and observes how the process ends. Used by the
// integration suite (H5) and the smoke test.
import { spawn } from "node:child_process"
import { fileURLToPath } from "node:url"

export const LIFECYCLE_CHILD = fileURLToPath(new URL("lifecycle-child.mjs", import.meta.url))
const MARKER_TIMEOUT_MS = 20_000

/**
 * @typedef {object} ChildExit
 * @property {number | null} code exit code
 * @property {string | null} signal terminating signal
 * @property {number} at epoch ms of the exit
 */

/**
 * @typedef {object} ChildHandle
 * @property {number} markerAt epoch ms printed with the marker
 * @property {string[]} fields marker fields between name and timestamp
 * @property {Promise<ChildExit>} exit resolves when the process ended
 * @property {() => string} stderr everything the child wrote to stderr
 * @property {() => void} kill SIGKILL
 */

/**
 * @typedef {object} ChildConnection
 * @property {string} host sshd host
 * @property {number} port sshd port
 * @property {string} user login user
 * @property {string} keyPath private key file
 * @property {string} hostKeyBase64 the host key the child accepts
 */

/**
 * @param connection where and how the child logs in
 * @param [extra] COMMAND and STREAM_BYTES
 * @returns process.env plus the SSH_NATIVE_CHILD_* variables
 */
export function childEnvironment(connection, extra = {}) {
  return {
    ...process.env,
    SSH_NATIVE_CHILD_HOST: connection.host,
    SSH_NATIVE_CHILD_HOST_KEY: connection.hostKeyBase64,
    SSH_NATIVE_CHILD_KEY: connection.keyPath,
    SSH_NATIVE_CHILD_PORT: String(connection.port),
    SSH_NATIVE_CHILD_USER: connection.user,
    ...extra,
  }
}

/**
 * @param stdout the output so far
 * @param marker the marker name
 * @returns the fields and timestamp of the marker line, if printed
 */
function findMarker(stdout, marker) {
  const line = stdout.split("\n").find((entry) => entry.startsWith(`${marker} `))
  if (!line) return null
  const parts = line.trim().split(" ")
  return { at: Number(parts.at(-1)), fields: parts.slice(1, -1) }
}

/**
 * Spawns the child and resolves once it printed `marker`.
 *
 * @param mode the scenario
 * @param env environment from childEnvironment()
 * @param marker the marker name to wait for
 * @returns the running child
 */
export function startChild(mode, env, marker) {
  const child = spawn(process.execPath, [LIFECYCLE_CHILD, mode], {
    env,
    stdio: ["ignore", "pipe", "pipe"],
  })
  let stdout = ""
  let stderr = ""
  child.stderr.on("data", (data) => {
    stderr += data
  })
  /** @type {Promise<ChildExit>} */
  const exit = new Promise((resolve) => {
    child.once("exit", (code, signal) => resolve({ at: Date.now(), code, signal }))
  })
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL")
      reject(new Error(`the child never printed ${marker}: ${stderr}`))
    }, MARKER_TIMEOUT_MS)
    exit.then((ended) => {
      clearTimeout(timer)
      reject(new Error(`the child exited before ${marker}: ${JSON.stringify(ended)} ${stderr}`))
    })
    child.stdout.on("data", (data) => {
      stdout += data
      const found = findMarker(stdout, marker)
      if (!found) return
      clearTimeout(timer)
      resolve({
        exit,
        fields: found.fields,
        kill: () => child.kill("SIGKILL"),
        markerAt: found.at,
        stderr: () => stderr,
      })
    })
  })
}

/**
 * @param handle a started child
 * @param ms how long to wait
 * @returns the exit, or `null` if the child still runs after `ms`
 */
export function exitWithin(handle, ms) {
  /** @type {ReturnType<typeof setTimeout> | undefined} */
  let timer
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => resolve(null), ms)
  })
  return Promise.race([handle.exit, timeout]).finally(() => clearTimeout(timer))
}
