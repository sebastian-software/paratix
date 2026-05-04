import type { Readable, Writable } from "node:stream"
import type { Client, SFTPWrapper } from "ssh2"

import { randomUUID } from "node:crypto"
import { createReadStream, createWriteStream, renameSync, unlinkSync } from "node:fs"
import { dirname, join } from "node:path"

/** Default timeout for SFTP transfers in milliseconds (2 minutes). */
export const SFTP_TIMEOUT = 120_000

type TransferSettlement = {
  rejectOnce: (reason: Error) => void
  resolveOnce: () => void
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

/**
 * Wire up stream event handlers with a timeout guard, then pipe.
 *
 * @param options - Stream piping options including timeout configuration.
 * @param options.completionEvents - Stream events that mark a successful transfer.
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
    clearTimer: () => {
      clearTimeout(timer)
    },
    reject,
    resolve,
    sftp,
  })

  for (const completionEvent of completionEvents) {
    writeStream.on(completionEvent, () => {
      settlement.resolveOnce()
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
 */
// eslint-disable-next-line max-params -- timeout parameter extends the existing signature
export async function sftpDownload(
  client: Client,
  remotePath: string,
  localPath: string,
  timeout = SFTP_TIMEOUT
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

    client.sftp((error, sftp) => {
      if (error) {
        rejectWithCleanup(error)
        return
      }

      let readStream: Readable | undefined
      let writeStream: Writable | undefined
      try {
        readStream = sftp.createReadStream(remotePath)
        // eslint-disable-next-line security/detect-non-literal-fs-filename
        writeStream = createWriteStream(temporaryPath, { mode: 0o600 })
        shouldCleanupTemporaryFile = true
      } catch (streamError) {
        if (readStream !== undefined && typeof readStream.destroy === "function") {
          readStream.destroy()
        }
        sftp.end()
        rejectWithCleanup(
          streamError instanceof Error
            ? streamError
            : new Error(`Failed to create SFTP download streams: ${String(streamError)}`)
        )
        return
      }

      wireStreams({
        completionEvents: ["finish"],
        readStream,
        reject: rejectWithCleanup,
        resolve: () => {
          try {
            // eslint-disable-next-line security/detect-non-literal-fs-filename
            renameSync(temporaryPath, localPath)
            resolve()
          } catch (finalizeError) {
            rejectWithCleanup(
              finalizeError instanceof Error
                ? finalizeError
                : new Error(`Failed to finalize SFTP download: ${String(finalizeError)}`)
            )
          }
        },
        sftp,
        timeout,
        timeoutMessage: `SFTP download timed out after ${timeout}ms: ${remotePath}`,
        writeStream,
      })
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
 */
// eslint-disable-next-line max-params -- timeout parameter extends the existing signature
export async function sftpUpload(
  client: Client,
  localPath: string,
  remotePath: string,
  timeout = SFTP_TIMEOUT
): Promise<void> {
  return new Promise((resolve, reject) => {
    client.sftp((error, sftp) => {
      if (error) {
        reject(error)
        return
      }

      let readStream: Readable | undefined
      let writeStream: Writable | undefined
      try {
        // eslint-disable-next-line security/detect-non-literal-fs-filename
        readStream = createReadStream(localPath)
        writeStream = sftp.createWriteStream(remotePath, { mode: 0o600 })
      } catch (streamError) {
        if (readStream !== undefined && typeof readStream.destroy === "function") {
          readStream.destroy()
        }
        sftp.end()
        reject(
          streamError instanceof Error
            ? streamError
            : new Error(`Failed to create SFTP upload streams: ${String(streamError)}`)
        )
        return
      }

      wireStreams({
        completionEvents: ["close", "finish"],
        readStream,
        reject,
        resolve,
        sftp,
        timeout,
        timeoutMessage: `SFTP upload timed out after ${timeout}ms: ${remotePath}`,
        writeStream,
      })
    })
  })
}
