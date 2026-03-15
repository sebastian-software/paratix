import type { Client } from "ssh2"

import { createReadStream, createWriteStream } from "node:fs"

/**
 * Transfer a remote file to a local path via SFTP.
 *
 * @param client - The connected ssh2 client.
 * @param remotePath - Source path on the remote host.
 * @param localPath - Destination path on the local filesystem.
 */
export async function sftpDownload(
  client: Client,
  remotePath: string,
  localPath: string
): Promise<void> {
  return new Promise((resolve, reject) => {
    client.sftp((error, sftp) => {
      if (error) {
        reject(error)
        return
      }

      const readStream = sftp.createReadStream(remotePath)
      // eslint-disable-next-line security/detect-non-literal-fs-filename
      const writeStream = createWriteStream(localPath)

      let settled = false

      writeStream.on("close", () => {
        sftp.end()
        resolve()
      })
      writeStream.on("error", (writeError: Error) => {
        if (settled) return
        settled = true
        readStream.destroy()
        if (typeof writeStream.destroy === "function") writeStream.destroy()
        sftp.end()
        reject(writeError)
      })
      readStream.on("error", (readError: Error) => {
        if (settled) return
        settled = true
        if (typeof readStream.destroy === "function") readStream.destroy()
        if (typeof writeStream.destroy === "function") writeStream.destroy()
        sftp.end()
        reject(readError)
      })
      readStream.pipe(writeStream)
    })
  })
}

/**
 * Transfer a local file to a remote path via SFTP.
 *
 * @param client - The connected ssh2 client.
 * @param localPath - Source path on the local filesystem.
 * @param remotePath - Destination path on the remote host.
 */
export async function sftpUpload(
  client: Client,
  localPath: string,
  remotePath: string
): Promise<void> {
  return new Promise((resolve, reject) => {
    client.sftp((error, sftp) => {
      if (error) {
        reject(error)
        return
      }

      // eslint-disable-next-line security/detect-non-literal-fs-filename
      const readStream = createReadStream(localPath)
      const writeStream = sftp.createWriteStream(remotePath)

      let settled = false

      writeStream.on("close", () => {
        sftp.end()
        resolve()
      })
      writeStream.on("error", (writeError: Error) => {
        if (settled) return
        settled = true
        if (typeof readStream.destroy === "function") readStream.destroy()
        if (typeof writeStream.destroy === "function") writeStream.destroy()
        sftp.end()
        reject(writeError)
      })
      readStream.on("error", (readError: Error) => {
        if (settled) return
        settled = true
        if (typeof readStream.destroy === "function") readStream.destroy()
        if (typeof writeStream.destroy === "function") writeStream.destroy()
        sftp.end()
        reject(readError)
      })
      readStream.pipe(writeStream)
    })
  })
}
