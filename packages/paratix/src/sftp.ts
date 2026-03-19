import type { Readable, Writable } from "node:stream"
import type { Client, SFTPWrapper } from "ssh2"

import { randomUUID } from "node:crypto"
import { createReadStream, createWriteStream, renameSync, unlinkSync } from "node:fs"
import { dirname, join } from "node:path"

/** Default timeout for SFTP transfers in milliseconds (2 minutes). */
export const SFTP_TIMEOUT = 120_000

/**
 * Wire up stream event handlers with a timeout guard, then pipe.
 *
 * @param options - Stream piping options including timeout configuration.
 * @param options.readStream - The source stream to read from.
 * @param options.reject - Promise reject callback.
 * @param options.resolve - Promise resolve callback.
 * @param options.sftp - The SFTP wrapper to close on completion.
 * @param options.timeout - Maximum time in ms before the transfer is aborted.
 * @param options.timeoutMessage - Error message to use when the transfer times out.
 * @param options.writeStream - The destination stream to write to.
 */
function wireStreams(options: {
  readStream: Readable
  reject: (reason: Error) => void
  resolve: () => void
  sftp: SFTPWrapper
  timeout: number
  timeoutMessage: string
  writeStream: Writable
}): void {
  const { readStream, reject, resolve, sftp, timeout, timeoutMessage, writeStream } = options

  let settled = false

  const timer = setTimeout(() => {
    if (settled) return
    settled = true
    readStream.destroy()
    writeStream.destroy()
    sftp.end()
    reject(new Error(timeoutMessage))
  }, timeout)

  writeStream.on("close", () => {
    clearTimeout(timer)
    if (settled) return
    settled = true
    sftp.end()
    resolve()
  })
  writeStream.on("error", (writeError: Error) => {
    clearTimeout(timer)
    if (settled) return
    settled = true
    readStream.destroy()
    if (typeof writeStream.destroy === "function") writeStream.destroy()
    sftp.end()
    reject(writeError)
  })
  readStream.on("error", (readError: Error) => {
    clearTimeout(timer)
    if (settled) return
    settled = true
    if (typeof readStream.destroy === "function") readStream.destroy()
    if (typeof writeStream.destroy === "function") writeStream.destroy()
    sftp.end()
    reject(readError)
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

      const readStream = sftp.createReadStream(remotePath)
      // eslint-disable-next-line security/detect-non-literal-fs-filename
      const writeStream = createWriteStream(temporaryPath, { mode: 0o600 })
      shouldCleanupTemporaryFile = true

      wireStreams({
        readStream,
        reject: rejectWithCleanup,
        resolve: () => {
          // eslint-disable-next-line security/detect-non-literal-fs-filename
          renameSync(temporaryPath, localPath)
          resolve()
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

      // eslint-disable-next-line security/detect-non-literal-fs-filename
      const readStream = createReadStream(localPath)
      const writeStream = sftp.createWriteStream(remotePath, { mode: 0o600 })

      wireStreams({
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
