// Local command helpers of the integration harness: running a tool with a
// timeout and probing whether a tool or the Docker daemon is available.
import { execFile, spawnSync } from "node:child_process"

const DEFAULT_TIMEOUT_MS = 30_000
const OUTPUT_TAIL = 4096
const MAX_BUFFER = 16 * 1024 * 1024

/**
 * @typedef {object} RunOptions
 * @property {string} [input] stdin for the command
 * @property {number} [timeoutMs] deadline, default 30 s
 * @property {Record<string, string | undefined>} [env] environment
 * @property {string} [cwd] working directory
 * @property {AbortSignal} [signal] kills the command when aborted
 */

/**
 * @param text command output
 * @returns its last few KiB
 */
function tail(text) {
  return text.length > OUTPUT_TAIL ? text.slice(-OUTPUT_TAIL) : text
}

/**
 * Runs a command and resolves with its stdout. Arguments never pass through
 * a shell. A failure carries the output tail, never the stdin.
 *
 * @param command the executable
 * @param args its arguments
 * @param [options] stdin, timeout, environment, working directory, abort signal
 * @returns stdout
 */
export function runTool(command, args, options = {}) {
  const { cwd, env, input, signal, timeoutMs = DEFAULT_TIMEOUT_MS } = options
  return new Promise((resolve, reject) => {
    const child = execFile(
      command,
      args,
      { cwd, encoding: "utf8", env, maxBuffer: MAX_BUFFER, signal, timeout: timeoutMs },
      (error, stdout, stderr) => {
        if (error) {
          const detail = [tail(stdout), tail(stderr)].filter(Boolean).join("\n").trim()
          reject(new Error(`${command} ${args[0] ?? ""} failed: ${detail}`, { cause: error }))
          return
        }
        resolve(stdout)
      }
    )
    // A tool that exits without reading stdin makes the write fail with EPIPE.
    child.stdin?.on("error", () => {})
    child.stdin?.end(input ?? "")
  })
}

/**
 * @param command an executable name or path
 * @returns whether it can be started (a usage error still counts as present)
 */
export function hasTool(command) {
  const probe = spawnSync(command, ["-?"], { stdio: "ignore", timeout: 10_000 })
  return probe.error === undefined
}

/**
 * @param commands executables the target needs
 * @returns a reason naming the missing ones, or `null`
 */
export function missingTools(commands) {
  const missing = commands.filter((command) => !hasTool(command))
  return missing.length === 0 ? null : `missing tools: ${missing.join(", ")}`
}

/** @returns whether `docker info` succeeds */
export function isDockerReachable() {
  const probe = spawnSync("docker", ["info"], { stdio: "ignore", timeout: 30_000 })
  return probe.status === 0
}
