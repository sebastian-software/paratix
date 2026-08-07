/**
 * Process plumbing for the `op` CLI: spawn a command, feed it on stdin, capture
 * its output within bounded buffers, and turn a failed invocation into a
 * contextual error.
 *
 * Extracted from `op.ts` — like `opSpawnError.ts`, `opOutputCapture.ts` and
 * `opFailureMasking.ts` — to keep that module within the project max-lines cap.
 * The split also separates the child-process plumbing from the reference
 * resolution that drives it (`opReferenceResolution.ts`).
 */

import { type ChildProcess, spawn } from "node:child_process"

import { getRunnerAbortSignal } from "../runnerAbortSignal.js"
import {
  type BoundedOutputCapture,
  createBoundedOutputCapture,
  OP_OUTPUT_CAPTURE_LIMIT_BYTES,
} from "./opOutputCapture.js"
import { OpSpawnError } from "./opSpawnError.js"
import { attachSpawnLifecycle, killChildEscalating } from "./opSpawnLifecycle.js"

/**
 * Default upper bound for a single `op` CLI invocation. The 1Password helper
 * can deadlock on a biometric prompt or a stale agent socket; we kill the
 * child after this many milliseconds rather than hanging the runner. R-0000220.
 */
const DEFAULT_OP_TIMEOUT_MILLISECONDS = 60_000

const OP_INSTALL_HINT =
  "Install it from https://1password.com/downloads/command-line/ and ensure it is on PATH."

const OP_SIGNIN_HINT = "Run 'op signin' first to authenticate the current shell session."

const OP_AUTH_PATTERNS = [
  /not\s+signed\s+in/iv,
  /not\s+authorized/iv,
  /authentication\s+required/iv,
  /session\s+expired/iv,
  /session\s+invalid/iv,
]

function isAuthFailure(stderr: string): boolean {
  return OP_AUTH_PATTERNS.some((pattern) => pattern.test(stderr))
}

function describeSpawnError(command: string, error: unknown): Error {
  if (error instanceof Error && (error as NodeJS.ErrnoException).code === "ENOENT") {
    return new Error(`${command} CLI is not installed or not on PATH. ${OP_INSTALL_HINT}`)
  }
  return error instanceof Error ? error : new Error(String(error))
}

/** Options for {@link spawnWithInput}; extracted to keep the parameter count <= 3. */
type SpawnWithInputOptions = {
  /**
   * Optional override for the per-call timeout. Defaults to
   * {@link DEFAULT_OP_TIMEOUT_MILLISECONDS}; pass a non-positive value to
   * disable the timer.
   */
  timeoutMs?: number
}

/** Mutable IO state captured while a child is running. */
type SpawnIoState = { stderr: BoundedOutputCapture; stdout: BoundedOutputCapture }

/** Initial no-op detach used until {@link attachSpawnLifecycle} replaces it. */
const NOOP_DETACH = (): void => {
  /* placeholder until attachSpawnLifecycle wires the real detach */
}

/**
 * Wire stdout, stderr, error and close handlers onto a spawned child so the
 * helper resolves on success and rejects with a contextual error on failure.
 *
 * @param parameters - Wiring inputs.
 * @param parameters.child - The spawned child process.
 * @param parameters.command - The executable name used in error messages.
 * @param parameters.io - Mutable IO accumulator that captures stdout / stderr.
 * @param parameters.rejectOnce - Reject closure invoked on error / non-zero exit.
 * @param parameters.resolveOnce - Resolve closure invoked when the child exits 0.
 */
function attachSpawnIoHandlers(parameters: {
  child: ChildProcess
  command: string
  io: SpawnIoState
  rejectOnce: (error: Error) => void
  resolveOnce: (output: string) => void
}): void {
  const { child, command, io, rejectOnce, resolveOnce } = parameters
  child.stdout?.on("data", (chunk: Buffer) => {
    io.stdout.append(chunk)
  })
  child.stderr?.on("data", (chunk: Buffer) => {
    io.stderr.append(chunk)
  })
  child.on("error", (error) => {
    rejectOnce(describeSpawnError(command, error))
  })
  child.on("close", (code) => {
    if (code === 0) {
      if (io.stdout.exceededLimit()) {
        rejectOnce(
          new Error(
            `${command} stdout exceeded ${String(
              OP_OUTPUT_CAPTURE_LIMIT_BYTES
            )} bytes; refusing to return a truncated secret`
          )
        )
        return
      }
      resolveOnce(io.stdout.text())
      return
    }
    const stderr = io.stderr.text()
    const stdoutText = io.stdout.text()
    const hint = isAuthFailure(stderr) ? ` ${OP_SIGNIN_HINT}` : ""
    // R-0000589: attach the captured streams to the rejection so the
    // resolve failure path can fold them into the maskSecrets call.
    rejectOnce(
      new OpSpawnError(`${command} exited with code ${String(code)}: ${stderr}${hint}`, {
        stderr,
        stdout: stdoutText,
      })
    )
  })
  child.stdin?.once("error", (error) => {
    // R-0000711: mirror the synchronous failure paths in `feedStdinOrFail`
    // (R-0000573/R-0000641/R-0000678) — an async stdin `error` event (e.g. a
    // late EPIPE after the pipe was wired up) settles the promise via
    // `rejectOnce` but otherwise leaves the underlying ChildProcess running.
    // Send SIGTERM with SIGKILL escalation first so no orphaned op CLI
    // process outlives the rejected promise.
    killChildEscalating(child)
    rejectOnce(describeSpawnError(command, error))
  })
}

function feedStdinOrFail(parameters: {
  child: ChildProcess
  command: string
  input: string
  rejectOnce: (error: Error) => void
}): void {
  const { child, command, input, rejectOnce } = parameters
  // R-0000573: when the child exits before its stdin pipe is wired up
  // (e.g. spawn raced a SIGKILL or the binary refused exec) `child.stdin`
  // is null. The previous `child.stdin?.end(input)` would then silently
  // no-op and the promise would hang because neither `error` nor `close`
  // had fired yet. Surface the failure explicitly instead.
  if (child.stdin == null) {
    // R-0000641: without an active stdin pipe `rejectOnce` settles the
    // promise but leaves the underlying ChildProcess running. Trigger
    // SIGTERM with SIGKILL escalation so no orphaned 1Password CLI process
    // can hang past this function.
    killChildEscalating(child)
    rejectOnce(new Error(`${command} spawn failed: stdin unavailable`))
    return
  }
  try {
    child.stdin.end(input)
  } catch (error) {
    // R-0000678: mirror the null-stdin path above — if `stdin.end()` throws
    // synchronously (e.g. EPIPE) `rejectOnce` settles the promise but
    // leaves the underlying ChildProcess running. Send SIGTERM with
    // SIGKILL escalation first so no orphaned op CLI process outlives
    // the rejected promise.
    killChildEscalating(child)
    rejectOnce(describeSpawnError(command, error))
  }
}

/**
 * Spawn a command, write `input` to its stdin, and collect stdout.
 *
 * The child is bound to the runner abort signal returned by
 * {@link getRunnerAbortSignal}: when the runner observes SIGINT/SIGTERM the
 * spawned process is killed (SIGTERM → SIGKILL) instead of hanging on a
 * blocked `op` CLI (e.g. waiting on a biometric prompt). A configurable
 * timeout (default {@link DEFAULT_OP_TIMEOUT_MILLISECONDS}) bounds individual
 * invocations to keep the runner responsive even when no abort arrives. R-0000220.
 *
 * @param command - The executable to run.
 * @param commandArguments - Arguments for the command.
 * @param spawnOptions - Optional behaviour overrides (input, timeout).
 * @returns The stdout output as a string.
 */
export async function spawnWithInput(
  command: string,
  commandArguments: string[],
  spawnOptions: { input: string } & SpawnWithInputOptions
): Promise<string> {
  const { input } = spawnOptions
  const timeoutMs = spawnOptions.timeoutMs ?? DEFAULT_OP_TIMEOUT_MILLISECONDS
  if (getRunnerAbortSignal()?.aborted === true) {
    throw new Error(`${command} aborted before spawn — runner shutdown in progress`)
  }
  return new Promise<string>((resolve, reject) => {
    const child: ChildProcess = spawn(command, commandArguments, {
      stdio: ["pipe", "pipe", "pipe"],
    })
    let settled = false
    const io: SpawnIoState = {
      stderr: createBoundedOutputCapture("stderr"),
      stdout: createBoundedOutputCapture("stdout"),
    }
    let detachLifecycle: () => void = NOOP_DETACH
    const rejectOnce = (error: Error): void => {
      if (settled) return
      settled = true
      detachLifecycle()
      reject(error)
    }
    const resolveOnce = (output: string): void => {
      if (settled) return
      settled = true
      detachLifecycle()
      resolve(output)
    }
    attachSpawnIoHandlers({ child, command, io, rejectOnce, resolveOnce })
    detachLifecycle = attachSpawnLifecycle({ child, command, rejectOnce, timeoutMs })
    feedStdinOrFail({ child, command, input, rejectOnce })
  })
}
