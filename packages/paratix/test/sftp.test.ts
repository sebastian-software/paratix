import type { Client, SFTPWrapper } from "ssh2"

import { EventEmitter } from "node:events"
import {
  createReadStream,
  createWriteStream,
  type ReadStream,
  unlinkSync,
  type WriteStream,
} from "node:fs"
import { afterEach, describe, expect, it, vi } from "vitest"

import { sftpDownload, sftpUpload } from "../src/sftp.js"

// vi.mock is hoisted to the top of the file by vitest before any imports are
// evaluated, so the module under test receives the mocked version.
vi.mock("node:fs", () => ({
  createReadStream: vi.fn(),
  createWriteStream: vi.fn(),
  unlinkSync: vi.fn(),
}))

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Minimal stream mock that supports piping, destroy, and emitting error events. */
type SftpMockStream = {
  destroy: ReturnType<typeof vi.fn>
  pipe: ReturnType<typeof vi.fn>
} & EventEmitter

class MockReadableStream extends EventEmitter {
  public destroy = vi.fn()
  public pipe = vi.fn()
}

function makeMockStream(): SftpMockStream {
  return new MockReadableStream() as SftpMockStream
}

function makeSftpSession() {
  const sftpReadStream = makeMockStream()
  const sftpWriteStream = Object.assign(new EventEmitter(), { destroy: vi.fn() })
  const sftpEnd = vi.fn()

  const sftp = {
    createReadStream: vi
      .fn()
      .mockReturnValue(sftpReadStream) as unknown as SFTPWrapper["createReadStream"],
    createWriteStream: vi
      .fn()
      .mockReturnValue(sftpWriteStream) as unknown as SFTPWrapper["createWriteStream"],
    end: sftpEnd as unknown as SFTPWrapper["end"],
  } as unknown as SFTPWrapper

  return { sftp, sftpEnd, sftpReadStream, sftpWriteStream }
}

function makeClientMock(sftp: SFTPWrapper): Client {
  return {
    sftp: vi.fn().mockImplementation((cb: Parameters<Client["sftp"]>[0]) => {
      cb(undefined, sftp)
    }),
  } as unknown as Client
}

// ---------------------------------------------------------------------------
// sftpDownload
// ---------------------------------------------------------------------------

describe("sftpDownload", () => {
  afterEach(() => {
    vi.resetAllMocks()
  })

  it("rejects when the sftp callback returns an error", async () => {
    const connectionError = new Error("sftp session failed")
    const client = {
      sftp: vi.fn().mockImplementation((cb: Parameters<Client["sftp"]>[0]) => {
        cb(connectionError, undefined as unknown as SFTPWrapper)
      }),
    } as unknown as Client

    await expect(sftpDownload(client, "/remote/file.txt", "/local/file.txt")).rejects.toThrow(
      "sftp session failed"
    )
  })

  it("rejects when the readStream emits an error (regression: missing error handler)", async () => {
    // Arrange
    const { sftp, sftpReadStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = new EventEmitter()
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    const readError = new Error("remote read stream broke")

    // Act — start the promise, then synchronously emit the error
    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt")
    sftpReadStream.emit("error", readError)

    // Assert — promise must reject, not hang
    await expect(promise).rejects.toThrow("remote read stream broke")
  })

  it("closes the sftp session when the readStream emits an error", async () => {
    // Arrange
    const { sftp, sftpEnd, sftpReadStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = new EventEmitter()
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    // Act
    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt")
    sftpReadStream.emit("error", new Error("disk error"))
    await promise.catch(() => {
      /* expected rejection */
    })

    // Assert — sftp session must be closed so no resource leak occurs
    expect(sftpEnd).toHaveBeenCalledOnce()
  })

  it("rejects when the local writeStream emits an error", async () => {
    // Arrange
    const { sftp } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = new EventEmitter()
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    const writeError = new Error("local write stream broke")

    // Act — start the promise, then synchronously emit the error
    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt")
    localWriteStream.emit("error", writeError)

    // Assert — promise must reject, not hang
    await expect(promise).rejects.toThrow("local write stream broke")
  })

  it("removes the incomplete local file when the download fails", async () => {
    const { sftp } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = new EventEmitter()
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt")
    localWriteStream.emit("error", new Error("local write stream broke"))

    await expect(promise).rejects.toThrow("local write stream broke")
    expect(vi.mocked(unlinkSync)).toHaveBeenCalledOnce()
    expect(vi.mocked(unlinkSync)).toHaveBeenCalledWith("/local/file.txt")
  })

  it("closes the sftp session when the local writeStream emits an error", async () => {
    // Arrange
    const { sftp, sftpEnd } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = new EventEmitter()
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    // Act
    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt")
    localWriteStream.emit("error", new Error("disk write error"))
    await promise.catch(() => {
      /* expected rejection */
    })

    // Assert — sftp session must be closed so no resource leak occurs
    expect(sftpEnd).toHaveBeenCalledOnce()
  })

  it("resolves when the local writeStream emits close", async () => {
    // Arrange
    const { sftp } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = new EventEmitter()
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    // Act — start the promise, then simulate a successful transfer completion
    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt")
    localWriteStream.emit("close")

    // Assert — promise must resolve on successful transfer
    await expect(promise).resolves.toBeUndefined()
  })

  // ---------------------------------------------------------------------------
  // BUG DOCUMENTATION: missing destroy() on counterpart stream
  // ---------------------------------------------------------------------------

  it("BUG: destroys the local writeStream when the readStream emits an error", async () => {
    // Arrange
    const { sftp, sftpReadStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = Object.assign(new EventEmitter(), { destroy: vi.fn() })
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    // Act
    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt")
    sftpReadStream.emit("error", new Error("remote read error"))
    await promise.catch(() => {
      /* expected rejection */
    })

    // Assert — writeStream.destroy() must be called to prevent a resource leak.
    // BUG: Currently NOT called → this test fails intentionally to document the bug.
    expect(localWriteStream.destroy).toHaveBeenCalledOnce()
  })

  it("BUG: destroys the readStream when the local writeStream emits an error", async () => {
    // Arrange
    const { sftp, sftpReadStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = Object.assign(new EventEmitter(), { destroy: vi.fn() })
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    // Act
    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt")
    localWriteStream.emit("error", new Error("local write error"))
    await promise.catch(() => {
      /* expected rejection */
    })

    // Assert — readStream.destroy() must be called to prevent a resource leak.
    // BUG: Currently NOT called → this test fails intentionally to document the bug.
    expect(sftpReadStream.destroy).toHaveBeenCalledOnce()
  })

  it("BUG: settled-flag prevents double reject and double sftp.end() when both streams error", async () => {
    // Arrange
    const { sftp, sftpEnd, sftpReadStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = Object.assign(new EventEmitter(), { destroy: vi.fn() })
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    // Act — emit errors on both streams back-to-back
    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt")
    sftpReadStream.emit("error", new Error("read error"))
    localWriteStream.emit("error", new Error("write error"))
    await promise.catch(() => {
      /* expected rejection */
    })

    // Assert — sftp.end() must be called exactly once despite two error events.
    // BUG: No settled-flag exists → sftp.end() is called twice → this test fails
    // intentionally to document the bug.
    expect(sftpEnd).toHaveBeenCalledOnce()
  })

  // ---------------------------------------------------------------------------
  // REGRESSION: settled-guard in close handler
  // ---------------------------------------------------------------------------

  it("regression: close event after readStream error does not resolve the already-rejected promise", async () => {
    // Arrange
    const { sftp, sftpReadStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = Object.assign(new EventEmitter(), { destroy: vi.fn() })
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    const readError = new Error("remote read stream error before close")

    // Act — emit error first, then close (simulates the real-world race condition
    // where the stream emits error and then close in sequence)
    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt")
    sftpReadStream.emit("error", readError)
    // Simulate close firing after the error (the previously missing settled-guard
    // would have caused this to call resolve() and swallow the rejection)
    localWriteStream.emit("close")

    // Assert — promise must still reject with the original error, not resolve
    await expect(promise).rejects.toThrow("remote read stream error before close")
  })

  it("regression: close event after writeStream error does not resolve the already-rejected promise", async () => {
    // Arrange
    const { sftp } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = Object.assign(new EventEmitter(), { destroy: vi.fn() })
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    const writeError = new Error("local write stream error before close")

    // Act — emit error first, then close
    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt")
    localWriteStream.emit("error", writeError)
    localWriteStream.emit("close")

    // Assert — promise must still reject with the original error, not resolve
    await expect(promise).rejects.toThrow("local write stream error before close")
  })

  // ---------------------------------------------------------------------------
  // Timeout tests
  // ---------------------------------------------------------------------------

  it("rejects when transfer times out", async () => {
    // Arrange
    vi.useFakeTimers()
    const { sftp } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = Object.assign(new EventEmitter(), { destroy: vi.fn() })
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    // Act — start download with a short timeout, then advance the timer past it
    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt", 5000)
    vi.advanceTimersByTime(5001)

    // Assert — promise must reject with a descriptive timeout message
    await expect(promise).rejects.toThrow("SFTP download timed out after 5000ms: /remote/file.txt")

    vi.useRealTimers()
  })

  it("destroys both streams and ends sftp session on timeout", async () => {
    // Arrange
    vi.useFakeTimers()
    const { sftp, sftpEnd, sftpReadStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = Object.assign(new EventEmitter(), { destroy: vi.fn() })
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    // Act — trigger the timeout
    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt", 5000)
    vi.advanceTimersByTime(5001)
    await promise.catch(() => {
      /* expected rejection */
    })

    // Assert — all resources must be cleaned up
    expect(sftpReadStream.destroy).toHaveBeenCalledOnce()
    expect(localWriteStream.destroy).toHaveBeenCalledOnce()
    expect(sftpEnd).toHaveBeenCalledOnce()

    vi.useRealTimers()
  })

  it("clears timeout on successful transfer", async () => {
    // Arrange
    vi.useFakeTimers()
    const { sftp } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = Object.assign(new EventEmitter(), { destroy: vi.fn() })
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    // Act — complete the transfer successfully before the timeout fires
    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt", 5000)
    localWriteStream.emit("close")
    await promise

    // Advance well past the timeout — must not cause additional effects
    vi.advanceTimersByTime(10_000)

    // Assert — promise already resolved; no extra sftp.end() from a late timeout
    await expect(promise).resolves.toBeUndefined()

    vi.useRealTimers()
  })

  it("clears timeout on stream error", async () => {
    // Arrange
    vi.useFakeTimers()
    const { sftp, sftpEnd, sftpReadStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = Object.assign(new EventEmitter(), { destroy: vi.fn() })
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    // Act — reject via stream error before the timeout fires
    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt", 5000)
    sftpReadStream.emit("error", new Error("stream error before timeout"))
    await promise.catch(() => {
      /* expected rejection */
    })

    // Advance well past the timeout — must not cause any additional cleanup calls
    vi.advanceTimersByTime(10_000)

    // Assert — sftp.end() was called exactly once (from the error handler, not the timeout)
    expect(sftpEnd).toHaveBeenCalledOnce()

    vi.useRealTimers()
  })
})

// ---------------------------------------------------------------------------
// sftpUpload
// ---------------------------------------------------------------------------

describe("sftpUpload", () => {
  afterEach(() => {
    vi.resetAllMocks()
  })

  it("rejects when the sftp callback returns an error", async () => {
    const connectionError = new Error("sftp session failed")
    const client = {
      sftp: vi.fn().mockImplementation((cb: Parameters<Client["sftp"]>[0]) => {
        cb(connectionError, undefined as unknown as SFTPWrapper)
      }),
    } as unknown as Client

    await expect(sftpUpload(client, "/local/file.txt", "/remote/file.txt")).rejects.toThrow(
      "sftp session failed"
    )
  })

  it("rejects when the local readStream emits an error (regression: missing error handler)", async () => {
    // Arrange
    const { sftp } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localReadStream = makeMockStream()
    vi.mocked(createReadStream).mockReturnValue(localReadStream as unknown as ReadStream)

    const readError = new Error("local read stream broke")

    // Act
    const promise = sftpUpload(client, "/local/file.txt", "/remote/file.txt")
    localReadStream.emit("error", readError)

    // Assert — promise must reject, not hang
    await expect(promise).rejects.toThrow("local read stream broke")
  })

  it("closes the sftp session when the local readStream emits an error", async () => {
    // Arrange
    const { sftp, sftpEnd } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localReadStream = makeMockStream()
    vi.mocked(createReadStream).mockReturnValue(localReadStream as unknown as ReadStream)

    // Act
    const promise = sftpUpload(client, "/local/file.txt", "/remote/file.txt")
    localReadStream.emit("error", new Error("disk error"))
    await promise.catch(() => {
      /* expected rejection */
    })

    // Assert — sftp session must be closed so no resource leak occurs
    expect(sftpEnd).toHaveBeenCalledOnce()
  })

  it("rejects when the remote writeStream emits an error", async () => {
    // Arrange
    const { sftp, sftpWriteStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localReadStream = makeMockStream()
    vi.mocked(createReadStream).mockReturnValue(localReadStream as unknown as ReadStream)

    const writeError = new Error("remote write stream broke")

    // Act — start the promise, then synchronously emit the error
    const promise = sftpUpload(client, "/local/file.txt", "/remote/file.txt")
    sftpWriteStream.emit("error", writeError)

    // Assert — promise must reject, not hang
    await expect(promise).rejects.toThrow("remote write stream broke")
  })

  it("closes the sftp session when the remote writeStream emits an error", async () => {
    // Arrange
    const { sftp, sftpEnd, sftpWriteStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localReadStream = makeMockStream()
    vi.mocked(createReadStream).mockReturnValue(localReadStream as unknown as ReadStream)

    // Act
    const promise = sftpUpload(client, "/local/file.txt", "/remote/file.txt")
    sftpWriteStream.emit("error", new Error("remote write error"))
    await promise.catch(() => {
      /* expected rejection */
    })

    // Assert — sftp session must be closed so no resource leak occurs
    expect(sftpEnd).toHaveBeenCalledOnce()
  })

  it("resolves when the remote writeStream emits close", async () => {
    // Arrange
    const { sftp, sftpWriteStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localReadStream = makeMockStream()
    vi.mocked(createReadStream).mockReturnValue(localReadStream as unknown as ReadStream)

    // Act — start the promise, then simulate a successful transfer completion
    const promise = sftpUpload(client, "/local/file.txt", "/remote/file.txt")
    sftpWriteStream.emit("close")

    // Assert — promise must resolve on successful transfer
    await expect(promise).resolves.toBeUndefined()
  })

  // ---------------------------------------------------------------------------
  // BUG DOCUMENTATION: missing destroy() on counterpart stream
  // ---------------------------------------------------------------------------

  it("BUG: destroys the remote writeStream when the local readStream emits an error", async () => {
    // Arrange
    const { sftp, sftpWriteStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localReadStream = makeMockStream()
    vi.mocked(createReadStream).mockReturnValue(localReadStream as unknown as ReadStream)

    // Act
    const promise = sftpUpload(client, "/local/file.txt", "/remote/file.txt")
    localReadStream.emit("error", new Error("local read error"))
    await promise.catch(() => {
      /* expected rejection */
    })

    // Assert — writeStream.destroy() must be called to prevent a resource leak.
    // BUG: Currently NOT called → this test fails intentionally to document the bug.
    expect(sftpWriteStream.destroy).toHaveBeenCalledOnce()
  })

  it("BUG: destroys the local readStream when the remote writeStream emits an error", async () => {
    // Arrange
    const { sftp, sftpWriteStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localReadStream = makeMockStream()
    vi.mocked(createReadStream).mockReturnValue(localReadStream as unknown as ReadStream)

    // Act
    const promise = sftpUpload(client, "/local/file.txt", "/remote/file.txt")
    sftpWriteStream.emit("error", new Error("remote write error"))
    await promise.catch(() => {
      /* expected rejection */
    })

    // Assert — readStream.destroy() must be called to prevent a resource leak.
    // BUG: Currently NOT called → this test fails intentionally to document the bug.
    expect(localReadStream.destroy).toHaveBeenCalledOnce()
  })

  it("BUG: settled-flag prevents double reject and double sftp.end() when both streams error", async () => {
    // Arrange
    const { sftp, sftpEnd, sftpWriteStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localReadStream = makeMockStream()
    vi.mocked(createReadStream).mockReturnValue(localReadStream as unknown as ReadStream)

    // Act — emit errors on both streams back-to-back
    const promise = sftpUpload(client, "/local/file.txt", "/remote/file.txt")
    localReadStream.emit("error", new Error("read error"))
    sftpWriteStream.emit("error", new Error("write error"))
    await promise.catch(() => {
      /* expected rejection */
    })

    // Assert — sftp.end() must be called exactly once despite two error events.
    // BUG: No settled-flag exists → sftp.end() is called twice → this test fails
    // intentionally to document the bug.
    expect(sftpEnd).toHaveBeenCalledOnce()
  })

  // ---------------------------------------------------------------------------
  // REGRESSION: settled-guard in close handler
  // ---------------------------------------------------------------------------

  it("regression: close event after localReadStream error does not resolve the already-rejected promise", async () => {
    // Arrange
    const { sftp, sftpWriteStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localReadStream = makeMockStream()
    vi.mocked(createReadStream).mockReturnValue(localReadStream as unknown as ReadStream)

    const readError = new Error("local read stream error before close")

    // Act — emit error on the local readStream first, then close on the writeStream
    // (simulates the real-world race condition where the stream emits error and
    // then close in sequence; the missing settled-guard in close would have caused
    // resolve() to fire and swallow the rejection)
    const promise = sftpUpload(client, "/local/file.txt", "/remote/file.txt")
    localReadStream.emit("error", readError)
    sftpWriteStream.emit("close")

    // Assert — promise must still reject with the original error, not resolve
    await expect(promise).rejects.toThrow("local read stream error before close")
  })

  it("regression: close event after remoteWriteStream error does not resolve the already-rejected promise", async () => {
    // Arrange
    const { sftp, sftpWriteStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localReadStream = makeMockStream()
    vi.mocked(createReadStream).mockReturnValue(localReadStream as unknown as ReadStream)

    const writeError = new Error("remote write stream error before close")

    // Act — emit error on the remote writeStream first, then close on the same stream
    const promise = sftpUpload(client, "/local/file.txt", "/remote/file.txt")
    sftpWriteStream.emit("error", writeError)
    sftpWriteStream.emit("close")

    // Assert — promise must still reject with the original error, not resolve
    await expect(promise).rejects.toThrow("remote write stream error before close")
  })

  // ---------------------------------------------------------------------------
  // Timeout tests
  // ---------------------------------------------------------------------------

  it("rejects when transfer times out", async () => {
    // Arrange
    vi.useFakeTimers()
    const { sftp } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localReadStream = makeMockStream()
    vi.mocked(createReadStream).mockReturnValue(localReadStream as unknown as ReadStream)

    // Act — start upload with a short timeout, then advance the timer past it
    const promise = sftpUpload(client, "/local/file.txt", "/remote/file.txt", 5000)
    vi.advanceTimersByTime(5001)

    // Assert — promise must reject with a descriptive timeout message
    await expect(promise).rejects.toThrow("SFTP upload timed out after 5000ms: /remote/file.txt")

    vi.useRealTimers()
  })

  it("destroys both streams and ends sftp session on timeout", async () => {
    // Arrange
    vi.useFakeTimers()
    const { sftp, sftpEnd, sftpWriteStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localReadStream = makeMockStream()
    vi.mocked(createReadStream).mockReturnValue(localReadStream as unknown as ReadStream)

    // Act — trigger the timeout
    const promise = sftpUpload(client, "/local/file.txt", "/remote/file.txt", 5000)
    vi.advanceTimersByTime(5001)
    await promise.catch(() => {
      /* expected rejection */
    })

    // Assert — all resources must be cleaned up
    expect(localReadStream.destroy).toHaveBeenCalledOnce()
    expect(sftpWriteStream.destroy).toHaveBeenCalledOnce()
    expect(sftpEnd).toHaveBeenCalledOnce()

    vi.useRealTimers()
  })

  it("clears timeout on successful transfer", async () => {
    // Arrange
    vi.useFakeTimers()
    const { sftp, sftpWriteStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localReadStream = makeMockStream()
    vi.mocked(createReadStream).mockReturnValue(localReadStream as unknown as ReadStream)

    // Act — complete the transfer successfully before the timeout fires
    const promise = sftpUpload(client, "/local/file.txt", "/remote/file.txt", 5000)
    sftpWriteStream.emit("close")
    await promise

    // Advance well past the timeout — must not cause additional effects
    vi.advanceTimersByTime(10_000)

    // Assert — promise already resolved; no extra sftp.end() from a late timeout
    await expect(promise).resolves.toBeUndefined()

    vi.useRealTimers()
  })

  it("clears timeout on stream error", async () => {
    // Arrange
    vi.useFakeTimers()
    const { sftp, sftpEnd, sftpWriteStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localReadStream = makeMockStream()
    vi.mocked(createReadStream).mockReturnValue(localReadStream as unknown as ReadStream)

    // Act — reject via stream error before the timeout fires
    const promise = sftpUpload(client, "/local/file.txt", "/remote/file.txt", 5000)
    sftpWriteStream.emit("error", new Error("stream error before timeout"))
    await promise.catch(() => {
      /* expected rejection */
    })

    // Advance well past the timeout — must not cause any additional cleanup calls
    vi.advanceTimersByTime(10_000)

    // Assert — sftp.end() was called exactly once (from the error handler, not the timeout)
    expect(sftpEnd).toHaveBeenCalledOnce()

    vi.useRealTimers()
  })
})
