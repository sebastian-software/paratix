import { type ChildProcess, spawn } from "node:child_process"

import { getRunnerAbortSignal } from "../runnerAbortSignal.js"

const MILLISECONDS_PER_SECOND = 1000
const SECONDS_PER_MINUTE = 60
const DEFAULT_RSYNC_TIMEOUT_MINUTES = 30
export const DEFAULT_RSYNC_TIMEOUT_MILLISECONDS =
  DEFAULT_RSYNC_TIMEOUT_MINUTES * SECONDS_PER_MINUTE * MILLISECONDS_PER_SECOND
const RSYNC_KILL_GRACE_MILLISECONDS = MILLISECONDS_PER_SECOND
const BYTES_PER_KIB = 1024
const RSYNC_OUTPUT_CAPTURE_LIMIT_KIB = 64
const RSYNC_OUTPUT_CAPTURE_LIMIT = RSYNC_OUTPUT_CAPTURE_LIMIT_KIB * BYTES_PER_KIB
const NOOP_DETACH = (): void => {
  /* placeholder until attachProcessLifecycle wires the real detach */
}

type BoundedOutputCapture = {
  append: (chunk: string) => void
  hasNonWhitespace: () => boolean
  text: () => string
}

export type RsyncProcessResult = {
  code: null | number
  hasStdout: boolean
  spawnError?: Error
  stderr: string
  stdout: string
}

function createBoundedOutputCapture(streamName: "stderr" | "stdout"): BoundedOutputCapture {
  const truncationMarker = `\n[paratix] rsync ${streamName} truncated after ${String(
    RSYNC_OUTPUT_CAPTURE_LIMIT
  )} characters\n`
  let captured = ""
  let hasOutput = false
  let truncated = false

  return {
    append(chunk: string): void {
      if (/\S/v.test(chunk)) hasOutput = true
      if (truncated) return

      const remaining = RSYNC_OUTPUT_CAPTURE_LIMIT - captured.length
      if (chunk.length <= remaining) {
        captured += chunk
        return
      }

      captured += chunk.slice(0, Math.max(0, remaining)) + truncationMarker
      truncated = true
    },
    hasNonWhitespace(): boolean {
      return hasOutput
    },
    text(): string {
      return captured
    },
  }
}

function killRsyncChildEscalating(child: ChildProcess): void {
  if (child.exitCode !== null) return
  try {
    child.kill("SIGTERM")
  } catch {
    // ignored — child may have exited between the guard and kill
  }
  setTimeout(() => {
    if (child.exitCode !== null) return
    try {
      child.kill("SIGKILL")
    } catch {
      // ignored — best-effort SIGKILL
    }
  }, RSYNC_KILL_GRACE_MILLISECONDS).unref()
}

function createProcessResult(parameters: {
  code: null | number
  spawnError?: Error
  stderr: BoundedOutputCapture
  stdout: BoundedOutputCapture
}): RsyncProcessResult {
  const { code, spawnError, stderr, stdout } = parameters
  return {
    code,
    hasStdout: stdout.hasNonWhitespace(),
    spawnError,
    stderr: stderr.text(),
    stdout: stdout.text(),
  }
}

function attachProcessLifecycle(parameters: {
  child: ChildProcess
  failOnClose: (error: Error) => void
  timeoutMs: number
}): () => void {
  const { child, failOnClose, timeoutMs } = parameters
  let timeoutHandle: NodeJS.Timeout | undefined
  const abortSignal = getRunnerAbortSignal()
  let abortListener: (() => void) | undefined

  if (timeoutMs > 0) {
    timeoutHandle = setTimeout(() => {
      failOnClose(new Error(`rsync timed out after ${String(timeoutMs)}ms`))
      killRsyncChildEscalating(child)
    }, timeoutMs)
    timeoutHandle.unref()
  }

  if (abortSignal !== undefined) {
    abortListener = (): void => {
      failOnClose(new Error("rsync aborted — runner shutdown in progress"))
      killRsyncChildEscalating(child)
    }
    if (abortSignal.aborted) {
      abortListener()
      return (): void => {
        if (timeoutHandle !== undefined) clearTimeout(timeoutHandle)
      }
    }
    abortSignal.addEventListener("abort", abortListener, { once: true })
  }

  return (): void => {
    if (timeoutHandle !== undefined) {
      clearTimeout(timeoutHandle)
      timeoutHandle = undefined
    }
    if (abortListener !== undefined && abortSignal !== undefined) {
      abortSignal.removeEventListener("abort", abortListener)
    }
  }
}

type WireRsyncChildParameters = {
  child: ChildProcess
  getPendingTerminationError: () => Error | undefined
  resolveOnce: (result: RsyncProcessResult) => void
  stderr: BoundedOutputCapture
  stdout: BoundedOutputCapture
}

function wireRsyncChildHandlers(parameters: WireRsyncChildParameters): void {
  const { child, getPendingTerminationError, resolveOnce, stderr, stdout } = parameters
  child.stdout?.setEncoding("utf8")
  child.stderr?.setEncoding("utf8")
  child.stdout?.on("data", (chunk: string) => {
    stdout.append(chunk)
  })
  child.stderr?.on("data", (chunk: string) => {
    stderr.append(chunk)
  })
  child.on("error", (error: Error) => {
    resolveOnce(createProcessResult({ code: null, spawnError: error, stderr, stdout }))
  })
  child.on("close", (code: null | number) => {
    resolveOnce(
      createProcessResult({
        code,
        spawnError: getPendingTerminationError(),
        stderr,
        stdout,
      })
    )
  })
}

/**
 * Run `rsync` and stream stdout/stderr into bounded diagnostic buffers.
 * R-0000040: replaces the previous `execFile` runner whose default 1 MiB
 * stdout buffer could trip `ERR_CHILD_PROCESS_STDIO_MAXBUFFER` on large
 * `--itemize-changes` outputs.
 *
 * @param rsyncArguments - The fully-built argv for the rsync invocation.
 * @param timeoutMs - Maximum runtime before the child is terminated.
 * @returns The captured stdout, stderr, and exit code.
 */
export async function runRsyncProcess(
  rsyncArguments: string[],
  timeoutMs: number
): Promise<RsyncProcessResult> {
  return new Promise((resolve) => {
    const child = spawn("rsync", rsyncArguments, { stdio: ["ignore", "pipe", "pipe"] })
    const stdout = createBoundedOutputCapture("stdout")
    const stderr = createBoundedOutputCapture("stderr")
    let settled = false
    let detachLifecycle = NOOP_DETACH
    let pendingTerminationError: Error | undefined

    const resolveOnce = (result: RsyncProcessResult): void => {
      if (settled) return
      settled = true
      detachLifecycle()
      resolve(result)
    }

    const failOnClose = (error: Error): void => {
      pendingTerminationError ??= error
    }

    wireRsyncChildHandlers({
      child,
      getPendingTerminationError: () => pendingTerminationError,
      resolveOnce,
      stderr,
      stdout,
    })

    detachLifecycle = attachProcessLifecycle({ child, failOnClose, timeoutMs })

    // R-0000570: when the runner is already aborted at spawn time,
    // `attachProcessLifecycle` schedules the abort listener which only flags
    // `pendingTerminationError` and kills the child. If `kill` fails and no
    // `error`/`close` event ever fires, the surrounding Promise would hang.
    // `resolveOnce` is idempotent, so calling it here is safe even though
    // a subsequent `close` event would otherwise have ended the wait.
    if (pendingTerminationError !== undefined) {
      resolveOnce(
        createProcessResult({
          code: null,
          spawnError: pendingTerminationError,
          stderr,
          stdout,
        })
      )
    }
  })
}
