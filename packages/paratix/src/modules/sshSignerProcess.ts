import { spawn } from "node:child_process"
import { chmod, mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"

const LIMIT = 1_048_576
const PRIVATE_DIRECTORY_MODE = 0o700
const TERMINATION_GRACE_MS = 250
const TIMEOUT = 60_000

export class HostCertificateError extends Error {
  public constructor(message: string) {
    super(message)
    this.name = "HostCertificateError"
  }
}

/**
 * Private per-invocation controller state; never consult personal CLI contexts.
 * @param body - Operation using this invocation's protected temporary directory.
 * @returns The operation result after temporary-state cleanup.
 */
export async function withSignerDirectory<T>(body: (directory: string) => Promise<T>): Promise<T> {
  const directory = await mkdtemp(join(tmpdir(), "paratix-host-signer-"))
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- fresh mkdtemp directory owned by this invocation
    await chmod(directory, PRIVATE_DIRECTORY_MODE)
    return await body(directory)
  } finally {
    await rm(directory, { force: true, recursive: true })
  }
}

/**
 * Shell-free, noninteractive, bounded process. Raw exceptions and streams never escape.
 * @param command - Controller executable to invoke without a shell.
 * @param args - Individual noninteractive command arguments.
 * @param options - Private directory, cancellation signal and safe diagnostic stage.
 * @param options.directory - Private working directory and isolated tool home.
 * @param options.signal - Cancellation signal for the bounded process group.
 * @param options.stage - Public operation label used instead of raw tool diagnostics.
 * @returns Bounded standard output after successful process exit.
 */
export async function signerProcess(
  command: string,
  args: string[],
  options: { directory: string; signal: AbortSignal; stage: string }
): Promise<string> {
  if (options.signal.aborted) throw new HostCertificateError("Host certificate signing aborted")
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.directory,
      detached: true,
      env: {
        HOME: options.directory,
        LANG: "C",
        LC_ALL: "C",
        PATH: process.env.PATH,
        SSH_ASKPASS_REQUIRE: "never",
        STEPPATH: options.directory,
      },
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    })
    let failure: string | undefined
    let size = 0
    const output: Buffer[] = []
    let escalation: ReturnType<typeof setTimeout> | undefined
    const kill = (reason: string): void => {
      failure ??= reason
      if (child.pid === undefined) return
      try {
        process.kill(-child.pid, "SIGTERM")
      } catch {
        /* Already exited. */
      }
      escalation ??= setTimeout(() => {
        try {
          if (child.pid !== undefined) process.kill(-child.pid, "SIGKILL")
        } catch {
          /* Already exited. */
        }
      }, TERMINATION_GRACE_MS)
    }
    const abort = (): void => {
      kill("aborted")
    }
    options.signal.addEventListener("abort", abort, { once: true })
    const timer = setTimeout(() => {
      kill("timed out; request outcome may be unknown")
    }, TIMEOUT)
    child.stdout.on("data", (chunk: Buffer) => {
      size += chunk.length
      if (size > LIMIT) kill("output exceeded limit")
      else output.push(chunk)
    })
    child.stderr.on("data", (chunk: Buffer) => {
      size += chunk.length
      if (size > LIMIT) kill("output exceeded limit")
    })
    child.on("error", () => {
      failure ??= "could not start controller tool"
    })
    child.on("close", (code) => {
      try {
        if (child.pid !== undefined) process.kill(-child.pid, "SIGKILL")
      } catch {
        /* No remaining controller-tool children. */
      }
      clearTimeout(timer)
      clearTimeout(escalation)
      options.signal.removeEventListener("abort", abort)
      if (failure !== undefined || code !== 0) {
        reject(
          new HostCertificateError(
            `Host certificate ${options.stage}: ${failure ?? "controller tool failed"}`
          )
        )
      } else resolve(Buffer.concat(output).toString("utf8"))
    })
    if (options.signal.aborted) abort()
  })
}
