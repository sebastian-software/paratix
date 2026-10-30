import assert from "node:assert/strict"
import { createRequire } from "node:module"
import { constants } from "node:os"
import { describe, it } from "node:test"

const require = createRequire(import.meta.url)
const { ERROR_CODES, INTERNAL_MESSAGE, toError } = require("../lib/errors.js")

const nativeError = (message) => new Error(message)

describe("error mapping", () => {
  it("parses the CODE|detail|message reason", () => {
    const error = toError(nativeError("SFTP_STATUS|3|the SFTP server returned an error status"))
    assert.equal(error.code, "SFTP_STATUS")
    assert.equal(error.sftpStatus, 3)
    assert.equal(error.detail, "3")
    assert.equal(error.message, "the SFTP server returned an error status")
  })

  it("adds errno and the syscall code for CONNECT_FAILED", () => {
    const error = toError(
      nativeError(
        `CONNECT_FAILED|${constants.errno.ECONNREFUSED}|the TCP connection could not be established`
      )
    )
    assert.equal(error.errno, constants.errno.ECONNREFUSED)
    assert.equal(error.syscallCode, "ECONNREFUSED")
  })

  it("keeps the fallback without a numeric SFTP status", () => {
    const error = toError(nativeError("SFTP_STATUS|unknown|status not exposed"))
    assert.equal(error.sftpStatus, undefined)
  })

  for (const raw of [
    nativeError("called `Option::unwrap()` on a `None` value"),
    nativeError("NOT_A_CODE|x|secret text"),
    nativeError("INTERNAL|x|panic text"),
    "AUTH_FAILED|x|a string, not an Error",
    undefined,
    { message: "AUTH_FAILED||not an Error instance" },
  ]) {
    const label = raw instanceof Error ? raw.message : JSON.stringify(raw)
    it(`maps ${label} to INTERNAL with the fixed message`, () => {
      const error = toError(raw)
      assert.equal(error.code, "INTERNAL")
      assert.equal(error.message, INTERNAL_MESSAGE)
      assert.equal(error.detail, undefined)
    })
  }

  it("uses exactly the error codes of ADR 0008", () => {
    assert.deepEqual([...ERROR_CODES].sort(), [
      "ABORTED",
      "AUTH_FAILED",
      "CHANNEL_OPEN_FAILED",
      "CONNECT_FAILED",
      "DISCONNECTED",
      "ENCRYPTED_KEY",
      "HOST_KEY_REJECTED",
      "INTERNAL",
      "PROTOCOL",
      "SFTP_STATUS",
      "TIMEOUT",
      "UNSUPPORTED_KEY",
    ])
  })
})
