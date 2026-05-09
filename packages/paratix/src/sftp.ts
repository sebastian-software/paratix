/* eslint-disable max-lines -- SFTP transfer helpers keep stream lifecycle wiring local */
import type { Writable } from "node:stream"
import type { Client, SFTPWrapper } from "ssh2"

import { randomUUID } from "node:crypto"
import { createReadStream, createWriteStream, unlinkSync } from "node:fs"
import { rename } from "node:fs/promises"
import { dirname, join } from "node:path"
import { Readable } from "node:stream"

/** Default timeout for SFTP transfers in milliseconds (2 minutes). */
export const SFTP_TIMEOUT = 120_000

type TransferSettlement = {
  rejectOnce: (reason: Error) => void
  resolveOnce: () => void
}

type TransferStreams = {
  readStream: Readable
  writeStream: Writable
}

function normalizeTransferError(error: unknown, message: string): Error {
  return error instanceof Error ? error : new Error(`${message}: ${String(error)}`)
}

function noopAbortCleanup(): void {
  // No subscription installed.
}

/**
 * R-0000255: short-circuit the openSftp wait when the SSH connection is torn
 * down externally (e.g. the SIGINT path in runner.ts). Without this, the
 * session-open promise would idle until the default timeout fires even
 * though the underlying transport is already gone. Returns a cleanup
 * function the caller invokes once the open path settles, plus an `aborted`
 * flag indicating that the abort already fired and the caller must return.
 *
 * @param connectionAbortSignal - Optional connection-level abort signal.
 * @param onAbort - Called synchronously when the abort fires before settle.
 * @returns Cleanup helper and aborted flag.
 */
function subscribeToConnectionAbort(
  connectionAbortSignal: AbortSignal | undefined,
  onAbort: () => void
): { aborted: boolean; cleanup: () => void } {
  if (connectionAbortSignal == null) {
    return { aborted: false, cleanup: noopAbortCleanup }
  }
  if (connectionAbortSignal.aborted) {
    onAbort()
    return { aborted: true, cleanup: noopAbortCleanup }
  }
  const handleAbort = (): void => {
    onAbort()
  }
  connectionAbortSignal.addEventListener("abort", handleAbort, { once: true })
  const cleanup = (): void => {
    connectionAbortSignal.removeEventListener("abort", handleAbort)
  }
  return { aborted: false, cleanup }
}

function openSftp(options: {
  client: Client
  connectionAbortSignal?: AbortSignal
  onOpen: (sftp: SFTPWrapper) => void
  reject: (reason: Error) => void
  timeout: number
  timeoutMessage: string
}): void {
  const { client, connectionAbortSignal, onOpen, reject, timeout, timeoutMessage } = options
  let settled = false
  // Holder so the timer / sftp callback can call into a still-mutable cleanup
  // reference once `subscribeToConnectionAbort` returns the real one below.
  const abortHandle: { cleanup: () => void } = { cleanup: noopAbortCleanup }
  const timer = setTimeout(() => {
    if (settled) return
    settled = true
    abortHandle.cleanup()
    client.end()
    reject(new Error(timeoutMessage))
  }, timeout)
  const subscription = subscribeToConnectionAbort(connectionAbortSignal, () => {
    if (settled) return
    settled = true
    clearTimeout(timer)
    reject(new Error("SFTP session aborted: ssh disconnect"))
  })
  abortHandle.cleanup = subscription.cleanup
  if (subscription.aborted) return
  try {
    client.sftp((error: Error | undefined, sftp: SFTPWrapper | undefined) => {
      if (settled) {
        sftp?.end()
        return
      }
      clearTimeout(timer)
      abortHandle.cleanup()
      settled = true
      if (error) {
        reject(error)
        return
      }
      if (sftp === undefined) {
        reject(new Error("Failed to open SFTP session: missing SFTP session"))
        return
      }
      onOpen(sftp)
    })
  } catch (openError) {
    clearTimeout(timer)
    abortHandle.cleanup()
    settled = true
    reject(normalizeTransferError(openError, "Failed to open SFTP session"))
  }
}

function createTransferSettlement(options: {
  clearTimer: () => void
  reject: (reason: Error) => void
  resolve: () => void
  sftp: SFTPWrapper
}): TransferSettlement {
  let settled = false

  return {
    rejectOnce(reason: Error) {
      options.clearTimer()
      if (settled) return
      settled = true
      options.sftp.end()
      options.reject(reason)
    },
    resolveOnce() {
      options.clearTimer()
      if (settled) return
      settled = true
      options.sftp.end()
      options.resolve()
    },
  }
}

function openDownloadStreams(
  sftp: SFTPWrapper,
  remotePath: string,
  temporaryPath: string
): TransferStreams {
  let readStream: Readable | undefined
  try {
    readStream = sftp.createReadStream(remotePath)
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    const writeStream = createWriteStream(temporaryPath, { mode: 0o600 })
    return { readStream, writeStream }
  } catch (streamError) {
    if (readStream !== undefined && typeof readStream.destroy === "function") {
      readStream.destroy()
    }
    throw normalizeTransferError(streamError, "Failed to create SFTP download streams")
  }
}

function openUploadStreams(
  sftp: SFTPWrapper,
  localPath: string,
  remotePath: string
): TransferStreams {
  let readStream: Readable | undefined
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    readStream = createReadStream(localPath)
    const writeStream = sftp.createWriteStream(remotePath, { mode: 0o600 })
    return { readStream, writeStream }
  } catch (streamError) {
    if (readStream !== undefined && typeof readStream.destroy === "function") {
      readStream.destroy()
    }
    throw normalizeTransferError(streamError, "Failed to create SFTP upload streams")
  }
}

function openContentUploadStreams(
  sftp: SFTPWrapper,
  content: string,
  remotePath: string
): TransferStreams {
  let readStream: Readable | undefined
  try {
    readStream = Readable.from([Buffer.from(content, "utf8")])
    const writeStream = sftp.createWriteStream(remotePath, { mode: 0o600 })
    return { readStream, writeStream }
  } catch (streamError) {
    if (readStream !== undefined && typeof readStream.destroy === "function") {
      readStream.destroy()
    }
    throw normalizeTransferError(streamError, "Failed to create SFTP content upload streams")
  }
}

/**
 * Wire up stream event handlers with a timeout guard, then pipe.
 *
 * @param options - Stream piping options including timeout configuration.
 * @param options.completionEvents - Stream events that mark a successful transfer.
 * @param options.connectionAbortSignal - Optional connection-level abort signal that destroys the streams when fired (R-0000255).
 * @param options.prematureCloseMessage - Error message for a close before a successful transfer.
 * @param options.readStream - The source stream to read from.
 * @param options.reject - Promise reject callback.
 * @param options.resolve - Promise resolve callback.
 * @param options.sftp - The SFTP wrapper to close on completion.
 * @param options.timeout - Maximum time in ms before the transfer is aborted.
 * @param options.timeoutMessage - Error message to use when the transfer times out.
 * @param options.writeStream - The destination stream to write to.
 */
function wireStreams(options: {
  completionEvents?: Array<"close" | "finish">
  connectionAbortSignal?: AbortSignal
  prematureCloseMessage?: string
  readStream: Readable
  reject: (reason: Error) => void
  resolve: () => void
  sftp: SFTPWrapper
  timeout: number
  timeoutMessage: string
  writeStream: Writable
}): void {
  const {
    completionEvents = ["finish"],
    connectionAbortSignal,
    prematureCloseMessage,
    readStream,
    reject,
    resolve,
    sftp,
    timeout,
    timeoutMessage,
    writeStream,
  } = options

  const timer = setTimeout(() => {
    readStream.destroy()
    writeStream.destroy()
    settlement.rejectOnce(new Error(timeoutMessage))
  }, timeout)
  const settlement = createTransferSettlement({
    clearTimer() {
      clearTimeout(timer)
      if (connectionAbortSignal != null) {
        connectionAbortSignal.removeEventListener("abort", handleConnectionAbort)
      }
    },
    reject,
    resolve,
    sftp,
  })

  // R-0000255: when the underlying SSH transport is torn down (e.g. the
  // SIGINT handler in runner.ts) any in-flight SFTP transfer would otherwise
  // sit idle until the default 120 s timeout fires, because client.sftp()
  // does NOT emit a stream error on its own when the parent connection
  // closes. Couple the transfer to a connection-level abort signal so an
  // external disconnect destroys the streams immediately.
  const handleConnectionAbort = (): void => {
    readStream.destroy()
    if (typeof writeStream.destroy === "function") writeStream.destroy()
    settlement.rejectOnce(new Error("SFTP transfer aborted: ssh disconnect"))
  }
  if (connectionAbortSignal != null) {
    if (connectionAbortSignal.aborted) {
      // Schedule via microtask so the settlement is wired up before the
      // synchronous abort handler fires; otherwise `settlement.rejectOnce`
      // would run before the readStream/writeStream listeners are attached.
      queueMicrotask(handleConnectionAbort)
    } else {
      connectionAbortSignal.addEventListener("abort", handleConnectionAbort, { once: true })
    }
  }

  for (const completionEvent of completionEvents) {
    writeStream.on(completionEvent, () => {
      settlement.resolveOnce()
    })
  }
  if (prematureCloseMessage !== undefined) {
    writeStream.on("close", () => {
      readStream.destroy()
      if (typeof writeStream.destroy === "function") writeStream.destroy()
      settlement.rejectOnce(new Error(prematureCloseMessage))
    })
  }
  writeStream.on("error", (writeError: Error) => {
    readStream.destroy()
    if (typeof writeStream.destroy === "function") writeStream.destroy()
    settlement.rejectOnce(writeError)
  })
  readStream.on("error", (readError: Error) => {
    if (typeof readStream.destroy === "function") readStream.destroy()
    if (typeof writeStream.destroy === "function") writeStream.destroy()
    settlement.rejectOnce(readError)
  })
  readStream.pipe(writeStream)
}

/**
 * Transfer a remote file to a local path via SFTP.
 *
 * @param client - The connected ssh2 client.
 * @param remotePath - Source path on the remote host.
 * @param localPath - Destination path on the local filesystem.
 * @param timeout - Maximum time in ms before the transfer is aborted.
 * @param connectionAbortSignal - Optional abort signal that fires when the
 *   underlying SSH transport is torn down. Triggers immediate stream
 *   destruction (R-0000255) so a SIGINT-driven `ssh.disconnect()` does not
 *   leave the transfer waiting for the default 120 s timeout.
 */
// eslint-disable-next-line max-params -- timeout / abort parameters extend the existing signature; cleanup/finalize logic is intentionally kept together
export async function sftpDownload(
  client: Client,
  remotePath: string,
  localPath: string,
  timeout = SFTP_TIMEOUT,
  connectionAbortSignal?: AbortSignal
): Promise<void> {
  return new Promise((resolve, reject) => {
    const temporaryPath = join(dirname(localPath), `.paratix-download-${randomUUID()}.tmp`)
    let shouldCleanupTemporaryFile = false

    const rejectWithCleanup = (reason: Error): void => {
      if (shouldCleanupTemporaryFile) {
        try {
          // eslint-disable-next-line security/detect-non-literal-fs-filename
          unlinkSync(temporaryPath)
        } catch {
          // Best effort cleanup: preserve the original transfer error.
        }
      }
      reject(reason)
    }

    openSftp({
      client,
      connectionAbortSignal,
      onOpen(sftp) {
        let streams: TransferStreams
        try {
          streams = openDownloadStreams(sftp, remotePath, temporaryPath)
          shouldCleanupTemporaryFile = true
        } catch (streamError) {
          sftp.end()
          rejectWithCleanup(normalizeTransferError(streamError, "Failed to create SFTP download"))
          return
        }

        wireStreams({
          completionEvents: ["finish"],
          connectionAbortSignal,
          readStream: streams.readStream,
          reject: rejectWithCleanup,
          resolve() {
            // R-0000148: use async rename so the event loop is not blocked on
            // network filesystems or large files. After a successful rename,
            // disable the cleanup flag so a late stray rejection cannot
            // unlink the freshly renamed final file.
            // eslint-disable-next-line security/detect-non-literal-fs-filename
            rename(temporaryPath, localPath).then(
              () => {
                shouldCleanupTemporaryFile = false
                resolve()
              },
              (finalizeError: unknown) => {
                rejectWithCleanup(
                  finalizeError instanceof Error
                    ? finalizeError
                    : new Error(`Failed to finalize SFTP download: ${String(finalizeError)}`)
                )
              }
            )
          },
          sftp,
          timeout,
          timeoutMessage: `SFTP download timed out after ${timeout}ms: ${remotePath}`,
          writeStream: streams.writeStream,
        })
      },
      reject: rejectWithCleanup,
      timeout,
      timeoutMessage: `SFTP download session timed out after ${timeout}ms: ${remotePath}`,
    })
  })
}

/**
 * Transfer a local file to a remote path via SFTP.
 *
 * @param client - The connected ssh2 client.
 * @param localPath - Source path on the local filesystem.
 * @param remotePath - Destination path on the remote host.
 * @param timeout - Maximum time in ms before the transfer is aborted.
 * @param connectionAbortSignal - Optional abort signal that fires when the
 *   underlying SSH transport is torn down (R-0000255).
 */
// eslint-disable-next-line max-params -- timeout / abort parameters extend the existing signature
export async function sftpUpload(
  client: Client,
  localPath: string,
  remotePath: string,
  timeout = SFTP_TIMEOUT,
  connectionAbortSignal?: AbortSignal
): Promise<void> {
  return new Promise((resolve, reject) => {
    openSftp({
      client,
      connectionAbortSignal,
      onOpen(sftp) {
        let streams: TransferStreams
        try {
          streams = openUploadStreams(sftp, localPath, remotePath)
        } catch (streamError) {
          sftp.end()
          reject(normalizeTransferError(streamError, "Failed to create SFTP upload"))
          return
        }

        wireStreams({
          completionEvents: ["finish"],
          connectionAbortSignal,
          prematureCloseMessage: `SFTP upload closed before finish: ${remotePath}`,
          readStream: streams.readStream,
          reject,
          resolve,
          sftp,
          timeout,
          timeoutMessage: `SFTP upload timed out after ${timeout}ms: ${remotePath}`,
          writeStream: streams.writeStream,
        })
      },
      reject,
      timeout,
      timeoutMessage: `SFTP upload session timed out after ${timeout}ms: ${remotePath}`,
    })
  })
}

/**
 * Transfer string content directly to a remote path via SFTP.
 *
 * @param client - The connected ssh2 client.
 * @param content - UTF-8 string content to transfer.
 * @param remotePath - Destination path on the remote host.
 * @param timeout - Maximum time in ms before the transfer is aborted.
 * @param connectionAbortSignal - Optional abort signal that fires when the
 *   underlying SSH transport is torn down (R-0000255).
 */
// eslint-disable-next-line max-params -- timeout / abort parameters mirror sftpUpload
export async function sftpUploadContent(
  client: Client,
  content: string,
  remotePath: string,
  timeout = SFTP_TIMEOUT,
  connectionAbortSignal?: AbortSignal
): Promise<void> {
  return new Promise((resolve, reject) => {
    openSftp({
      client,
      connectionAbortSignal,
      onOpen(sftp) {
        let streams: TransferStreams
        try {
          streams = openContentUploadStreams(sftp, content, remotePath)
        } catch (streamError) {
          sftp.end()
          reject(normalizeTransferError(streamError, "Failed to create SFTP content upload"))
          return
        }

        wireStreams({
          completionEvents: ["finish"],
          connectionAbortSignal,
          prematureCloseMessage: `SFTP content upload closed before finish: ${remotePath}`,
          readStream: streams.readStream,
          reject,
          resolve,
          sftp,
          timeout,
          timeoutMessage: `SFTP content upload timed out after ${timeout}ms: ${remotePath}`,
          writeStream: streams.writeStream,
        })
      },
      reject,
      timeout,
      timeoutMessage: `SFTP content upload session timed out after ${timeout}ms: ${remotePath}`,
    })
  })
}
