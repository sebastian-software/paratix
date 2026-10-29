import assert from "node:assert/strict"
import { once } from "node:events"
import { Readable } from "node:stream"
import { pipeline } from "node:stream/promises"
import { after, before, describe, it } from "node:test"

import { collect, connectWithKey } from "./helpers/binding.mjs"
import { clientKey, payload, sha256, startServer } from "./helpers/server.mjs"

// SFTP status codes (SSH File Transfer Protocol, version 3).
const NO_SUCH_FILE = 2
const PERMISSION_DENIED = 3
const FAILURE = 4
const ROUND_TRIP_PATH = "/round-trip"

/**
 * @param sftp the SFTP session
 * @param path remote path
 * @param data content
 * @returns resolves once the file is closed
 */
function writeFile(sftp, path, data) {
  return pipeline(Readable.from([data]), sftp.createWriteStream(path))
}

describe("sftp", () => {
  const key = clientKey()
  let server
  let session
  let sftp

  before(async () => {
    server = await startServer({ keys: [key.publicKey] })
    session = await connectWithKey(server, key)
    sftp = await session.sftp()
  })
  after(async () => {
    await sftp.end()
    session.destroy()
    await server.close()
  })

  it("writes with a mode and reads the file back", async () => {
    const data = payload(3 * 1024 * 1024 + 17)
    const stream = sftp.createWriteStream(ROUND_TRIP_PATH, { mode: 0o600 })
    await pipeline(Readable.from([data]), stream)
    assert.equal(stream.bytesWritten, data.length)
    const file = server.files.get(ROUND_TRIP_PATH)
    assert.equal(file.mode, 0o600)
    assert.deepEqual(file.modes, [0o600, 0o600], "mode on open and through fchmod")
    const back = await collect(sftp.createReadStream(ROUND_TRIP_PATH))
    assert.equal(sha256(back), sha256(data))
  })

  it("applies the mode to an existing file through fchmod", async () => {
    await writeFile(sftp, "/existing", Buffer.from("one"))
    await pipeline(
      Readable.from([Buffer.from("two")]),
      sftp.createWriteStream("/existing", { mode: 0o640 })
    )
    assert.equal(server.files.get("/existing").mode, 0o640)
  })

  it("reads an empty file", async () => {
    await writeFile(sftp, "/empty", Buffer.alloc(0))
    const content = await collect(sftp.createReadStream("/empty"))
    assert.equal(content.length, 0)
  })

  it("reports a missing file as SFTP_STATUS NO_SUCH_FILE", async () => {
    await assert.rejects(collect(sftp.createReadStream("/missing")), {
      code: "SFTP_STATUS",
      sftpStatus: NO_SUCH_FILE,
    })
  })

  it("reports a refused open for writing as SFTP_STATUS", async () => {
    await assert.rejects(writeFile(sftp, "/denied", Buffer.from("x")), {
      code: "SFTP_STATUS",
      sftpStatus: PERMISSION_DENIED,
    })
  })

  it("keeps the numeric status of a failed WRITE", async () => {
    await assert.rejects(writeFile(sftp, "/write-fails", payload(256 * 1024)), {
      code: "SFTP_STATUS",
      sftpStatus: FAILURE,
    })
  })

  it("keeps the numeric status of a failed CLOSE", async () => {
    await assert.rejects(writeFile(sftp, "/close-fails", Buffer.from("x")), {
      code: "SFTP_STATUS",
      sftpStatus: PERMISSION_DENIED,
    })
  })

  it("creates streams synchronously and reports errors as error events", async () => {
    const stream = sftp.createReadStream("/missing")
    const [error] = await once(stream, "error")
    assert.equal(error.code, "SFTP_STATUS")
  })
})
