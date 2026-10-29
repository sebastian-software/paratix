"use strict"

// SFTP streams. Both are created synchronously and open the remote file
// lazily in `construct()`; errors (including the open) arrive as `error`
// events, like ssh2's streams.

const { Readable, Writable } = require("node:stream")

const { callNativeSync, toError } = require("./errors.js")
const native = require("./native.js")
const { checkMode, checkPath } = require("./validate.js")

const DEFAULT_HIGH_WATER_MARK = 64 * 1024

/**
 * Runs a native promise factory and reports the outcome to a stream callback.
 *
 * @param start starts the native call
 * @param onValue receives the resolved value first
 * @param callback the stream callback
 */
function settle(start, onValue, callback) {
  let pending
  try {
    pending = start()
  } catch (error) {
    callback(toError(error))
    return
  }
  Promise.resolve(pending).then(
    (value) => {
      onValue(value)
      callback()
    },
    (error) => callback(toError(error))
  )
}

function noValue() {
  // The promise carries no value.
}

/** A Writable that also reports the byte count after `finish`. */
class SftpWriteStream extends Writable {
  /** @type {number | undefined} */
  bytesWritten = undefined
}

class SftpSession {
  #sftp

  /** @param sftp native SFTP handle */
  constructor(sftp) {
    this.#sftp = sftp
  }

  /**
   * Opens a remote file for reading.
   *
   * @param path remote path
   * @param [options] buffering
   * @returns the stream; open errors arrive as `error` events
   */
  createReadStream(path, options = {}) {
    const { highWaterMark = DEFAULT_HIGH_WATER_MARK } = options
    checkPath(path)
    const sftp = this.#sftp
    /** @type {unknown} */
    let reader = null
    let reading = false
    const stream = new Readable({
      construct(callback) {
        settle(
          () => native.sftpOpenRead(sftp, path),
          (opened) => {
            reader = opened
          },
          callback
        )
      },
      destroy(error, callback) {
        if (reader !== null) {
          try {
            native.sftpReaderClose(reader)
          } catch {
            // Already closed.
          }
        }
        callback(error)
      },
      highWaterMark,
      read() {
        if (reading) return
        reading = true
        settle(
          () => native.sftpReaderRead(reader),
          (chunk) => {
            reading = false
            stream.push(chunk ?? null)
          },
          (error) => {
            if (error) stream.destroy(error)
          }
        )
      },
    })
    return stream
  }

  /**
   * Opens a remote file for writing (create, truncate). `mode` is applied on
   * create and through an fchmod after open, so an existing file gets it too.
   *
   * @param path remote path
   * @param [options] file mode and buffering
   * @returns the stream; open errors arrive as `error` events
   */
  createWriteStream(path, options = {}) {
    const { highWaterMark = DEFAULT_HIGH_WATER_MARK, mode } = options
    checkPath(path)
    checkMode(mode)
    const sftp = this.#sftp
    /** @type {unknown} */
    let writer = null
    let ended = false
    const stream = new SftpWriteStream({
      construct(callback) {
        settle(
          () => native.sftpOpenWrite(sftp, path, mode ?? null),
          (opened) => {
            writer = opened
          },
          callback
        )
      },
      destroy(error, callback) {
        if (writer !== null && !ended) {
          ended = true
          // Release the native writer; the remote handle is closed.
          Promise.resolve()
            .then(() => native.sftpWriterEnd(writer))
            .catch(noValue)
        }
        callback(error)
      },
      final(callback) {
        ended = true
        settle(
          () => native.sftpWriterEnd(writer),
          (bytes) => {
            stream.bytesWritten = bytes
          },
          callback
        )
      },
      highWaterMark,
      write(chunk, _encoding, callback) {
        settle(() => native.sftpWriterWrite(writer, chunk), noValue, callback)
      },
    })
    return stream
  }

  /**
   * Closes the SFTP channel; open streams fail with DISCONNECTED.
   *
   * @returns resolves once the close was requested
   */
  async end() {
    callNativeSync(() => native.sftpEnd(this.#sftp))
  }
}

module.exports = { SftpSession }
