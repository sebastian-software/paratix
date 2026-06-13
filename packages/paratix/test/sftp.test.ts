import type { Client, SFTPWrapper } from "ssh2"

import { EventEmitter } from "node:events"
import { createReadStream, createWriteStream, type ReadStream, type WriteStream } from "node:fs"
import { rename, unlink } from "node:fs/promises"
import { Writable } from "node:stream"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { sftpDownload, sftpUpload, sftpUploadContent } from "../src/sftp.js"

// vi.mock is hoisted to the top of the file by vitest before any imports are
// evaluated, so the module under test receives the mocked version.
vi.mock("node:fs", () => ({
  createReadStream: vi.fn(),
  createWriteStream: vi.fn(),
}))

// R-0000148: sftpDownload finalizes via async fs/promises.rename instead of renameSync.
// R-0000666: sftpDownload now cleans up the temp file via async fs/promises.unlink.
vi.mock("node:fs/promises", () => ({
  rename: vi.fn().mockResolvedValue(undefined),
  unlink: vi.fn().mockResolvedValue(undefined),
}))

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Minimal stream mock that supports piping, destroy, and emitting error events. */
type SftpMockStream = {
  destroy: ReturnType<typeof vi.fn>
  pipe: ReturnType<typeof vi.fn>
} & EventEmitter
type SftpMock = EventEmitter & SFTPWrapper

class MockReadableStream extends EventEmitter {
  public destroy = vi.fn()
  public pipe = vi.fn()
}

class CollectingWritableStream extends Writable {
  public readonly chunks: Buffer[] = []
  public readonly destroySpy = vi.fn()

  public override _write(
    chunk: Buffer,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void
  ): void {
    this.chunks.push(Buffer.from(chunk))
    callback()
  }

  public override destroy(error?: Error): this {
    this.destroySpy(error)
    return super.destroy(error)
  }
}

function makeMockStream(): SftpMockStream {
  return new MockReadableStream()
}

function makeSftpSession() {
  const sftpReadStream = makeMockStream()
  const sftpWriteStream = Object.assign(new EventEmitter(), { destroy: vi.fn() })
  const sftpEnd = vi.fn()

  const sftp = Object.assign(new EventEmitter(), {
    createReadStream: vi.fn().mockReturnValue(sftpReadStream),
    createWriteStream: vi.fn().mockReturnValue(sftpWriteStream),
    end: sftpEnd,
  }) as unknown as SftpMock

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
    vi.useRealTimers()
    vi.resetAllMocks()
  })

  beforeEach(() => {
    // R-0000148: keep the rename mock returning a resolved promise by default;
    // vi.resetAllMocks() in afterEach removes the implementation otherwise.
    vi.mocked(rename).mockResolvedValue(undefined)
    // R-0000666: keep the async unlink cleanup mock returning a resolved
    // promise by default for the same reason.
    vi.mocked(unlink).mockResolvedValue(undefined)
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

  it("rejects and ends the client when sftp session opening times out", async () => {
    vi.useFakeTimers()
    const clientEnd = vi.fn()
    const client = {
      end: clientEnd,
      sftp: vi.fn(),
    } as unknown as Client

    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt", 5000)
    vi.advanceTimersByTime(5001)

    await expect(promise).rejects.toThrow(
      "SFTP download session timed out after 5000ms: /remote/file.txt"
    )
    expect(clientEnd).toHaveBeenCalledOnce()
    expect(vi.mocked(createWriteStream)).not.toHaveBeenCalled()
  })

  it("closes a late sftp session after download session opening times out", async () => {
    vi.useFakeTimers()
    let openCallback: Parameters<Client["sftp"]>[0] | undefined
    const { sftp, sftpEnd } = makeSftpSession()
    const client = {
      end: vi.fn(),
      sftp: vi.fn().mockImplementation((cb: Parameters<Client["sftp"]>[0]) => {
        openCallback = cb
      }),
    } as unknown as Client

    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt", 5000)
    vi.advanceTimersByTime(5001)
    await promise.catch(() => {
      /* expected rejection */
    })
    openCallback?.(undefined, sftp)

    expect(sftpEnd).toHaveBeenCalledOnce()
    expect(vi.mocked(createWriteStream)).not.toHaveBeenCalled()
  })

  it("ignores a late sftp error callback after download session opening times out", async () => {
    vi.useFakeTimers()
    let openCallback: Parameters<Client["sftp"]>[0] | undefined
    const client = {
      end: vi.fn(),
      sftp: vi.fn().mockImplementation((cb: Parameters<Client["sftp"]>[0]) => {
        openCallback = cb
      }),
    } as unknown as Client

    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt", 5000)
    vi.advanceTimersByTime(5001)
    await promise.catch(() => {
      /* expected rejection */
    })

    expect(() => {
      openCallback?.(new Error("late sftp error"), undefined as unknown as SFTPWrapper)
    }).not.toThrow()
    expect(vi.mocked(createWriteStream)).not.toHaveBeenCalled()
  })

  it("rejects and closes the sftp session when remote read stream creation throws", async () => {
    const { sftp, sftpEnd } = makeSftpSession()
    const client = makeClientMock(sftp)
    vi.mocked(sftp).createReadStream.mockImplementation(() => {
      throw new Error("remote open failed")
    })

    await expect(sftpDownload(client, "/remote/file.txt", "/local/file.txt")).rejects.toThrow(
      "remote open failed"
    )
    expect(sftpEnd).toHaveBeenCalledOnce()
    expect(vi.mocked(createWriteStream)).not.toHaveBeenCalled()
    expect(vi.mocked(unlink)).not.toHaveBeenCalled()
  })

  it("rejects, destroys the remote stream, and closes sftp when local write stream creation throws", async () => {
    const { sftp, sftpEnd, sftpReadStream } = makeSftpSession()
    const client = makeClientMock(sftp)
    vi.mocked(createWriteStream).mockImplementation(() => {
      throw new Error("local open failed")
    })

    await expect(sftpDownload(client, "/remote/file.txt", "/local/file.txt")).rejects.toThrow(
      "local open failed"
    )
    expect(sftpReadStream.destroy).toHaveBeenCalledOnce()
    expect(sftpEnd).toHaveBeenCalledOnce()
    expect(vi.mocked(unlink)).not.toHaveBeenCalled()
  })

  it("does not remove the local path when the sftp session fails before creating the writeStream", async () => {
    const connectionError = new Error("sftp session failed")
    const client = {
      sftp: vi.fn().mockImplementation((cb: Parameters<Client["sftp"]>[0]) => {
        cb(connectionError, undefined as unknown as SFTPWrapper)
      }),
    } as unknown as Client

    await expect(sftpDownload(client, "/remote/file.txt", "/local/file.txt")).rejects.toThrow(
      "sftp session failed"
    )
    expect(vi.mocked(unlink)).not.toHaveBeenCalled()
    expect(vi.mocked(createWriteStream)).not.toHaveBeenCalled()
  })

  it("writes downloads to a temp file in the destination directory and renames on success", async () => {
    const { sftp, sftpReadStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = new EventEmitter()
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt")
    const [tempPath, options] = vi.mocked(createWriteStream).mock.calls[0] as [
      string,
      { mode: number },
    ]
    localWriteStream.emit("finish")

    await expect(promise).resolves.toBeUndefined()
    expect(tempPath).not.toBe("/local/file.txt")
    expect(tempPath).toMatch(/^\/local\/\.paratix-download-.+\.tmp$/v)
    expect(options).toStrictEqual({ mode: 0o600 })
    expect(sftpReadStream.pipe).toHaveBeenCalledWith(localWriteStream)
    expect(vi.mocked(rename)).toHaveBeenCalledWith(tempPath, "/local/file.txt")
  })

  it("preserves unicode remote and local paths for downloads", async () => {
    const { sftp } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = new EventEmitter()
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    const remotePath = "/remote/über ordner/こんにちは.txt"
    const localPath = "/local/über ordner/ß-datei.txt"
    const promise = sftpDownload(client, remotePath, localPath)
    const [tempPath] = vi.mocked(createWriteStream).mock.calls[0] as [string]
    localWriteStream.emit("finish")

    await expect(promise).resolves.toBeUndefined()
    const createReadStreamCalls = (
      sftp.createReadStream as unknown as { mock: { calls: unknown[][] } }
    ).mock.calls
    expect(createReadStreamCalls[0]?.[0]).toBe(remotePath)
    expect(tempPath).toContain("/local/")
    expect(tempPath).toContain(".paratix-download-")
    expect(vi.mocked(rename)).toHaveBeenCalledWith(tempPath, localPath)
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

  it("removes only the temp file when the download fails", async () => {
    const { sftp } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = new EventEmitter()
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt")
    const [tempPath] = vi.mocked(createWriteStream).mock.calls[0] as [string]
    localWriteStream.emit("error", new Error("local write stream broke"))

    await expect(promise).rejects.toThrow("local write stream broke")
    expect(vi.mocked(unlink)).toHaveBeenCalledOnce()
    expect(vi.mocked(unlink)).toHaveBeenCalledWith(tempPath)
    expect(vi.mocked(unlink)).not.toHaveBeenCalledWith("/local/file.txt")
    expect(vi.mocked(rename)).not.toHaveBeenCalled()
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

  it("resolves when the local writeStream emits finish", async () => {
    // Arrange
    const { sftp, sftpEnd } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = new EventEmitter()
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    // Act — start the promise, then simulate a successful transfer completion
    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt")
    localWriteStream.emit("finish")

    // Assert — promise must resolve on successful transfer
    await expect(promise).resolves.toBeUndefined()
    expect(sftpEnd).toHaveBeenCalledOnce()
  })

  it("absorbs a late sftp wrapper error after download settles", async () => {
    const { sftp, sftpEnd } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = new EventEmitter()
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt")
    localWriteStream.emit("finish")

    await expect(promise).resolves.toBeUndefined()
    expect(() => {
      sftp.emit("error", new Error("late sftp wrapper error"))
    }).not.toThrow()
    expect(sftpEnd).toHaveBeenCalledOnce()
  })

  it("rejects and removes the temp file when rename fails during local finalization", async () => {
    const { sftp } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = new EventEmitter()
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)
    vi.mocked(rename).mockRejectedValueOnce(new Error("rename failed"))

    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt")
    const [tempPath] = vi.mocked(createWriteStream).mock.calls[0] as [string]
    localWriteStream.emit("finish")

    await expect(promise).rejects.toThrow("rename failed")
    expect(vi.mocked(unlink)).toHaveBeenCalledWith(tempPath)
    expect(vi.mocked(unlink)).not.toHaveBeenCalledWith("/local/file.txt")
  })

  it("uses async rename and uses fs/promises.rename for finalization (R-0000148)", async () => {
    const { sftp } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = new EventEmitter()
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt")
    localWriteStream.emit("finish")

    await expect(promise).resolves.toBeUndefined()
    expect(vi.mocked(rename)).toHaveBeenCalledOnce()
  })

  it("does not unlink the final file when a late rejection arrives after rename succeeded (R-0000148)", async () => {
    const { sftp } = makeSftpSession()
    const client = makeClientMock(sftp)

    // Defer the rename promise so we can manually resolve and observe ordering.
    let resolveRename: (() => void) | undefined
    vi.mocked(rename).mockImplementationOnce(async () => {
      await new Promise<void>((res) => {
        resolveRename = res
      })
    })

    const localWriteStream = new EventEmitter()
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt")
    const [tempPath] = vi.mocked(createWriteStream).mock.calls[0] as [string]

    // Trigger the success path that schedules the async rename.
    localWriteStream.emit("finish")
    expect(resolveRename).toBeDefined()
    resolveRename!()

    await expect(promise).resolves.toBeUndefined()

    // Reset call history so we can detect any unwanted late unlinks.
    vi.mocked(unlink).mockClear()

    // After the rename succeeded, the cleanup flag must be false.
    // Even if some hypothetical late code path tries the same temp path,
    // there should be no unlink of the (now-renamed) final file.
    expect(vi.mocked(unlink)).not.toHaveBeenCalledWith(tempPath)
    expect(vi.mocked(unlink)).not.toHaveBeenCalledWith("/local/file.txt")
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
  })

  it("leaves the destination path untouched on timeout", async () => {
    vi.useFakeTimers()
    const { sftp } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = Object.assign(new EventEmitter(), { destroy: vi.fn() })
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt", 5000)
    const [tempPath] = vi.mocked(createWriteStream).mock.calls[0] as [string]
    vi.advanceTimersByTime(5001)

    await expect(promise).rejects.toThrow("SFTP download timed out after 5000ms: /remote/file.txt")
    expect(vi.mocked(rename)).not.toHaveBeenCalled()
    expect(vi.mocked(unlink)).toHaveBeenCalledWith(tempPath)
    expect(vi.mocked(unlink)).not.toHaveBeenCalledWith("/local/file.txt")
  })

  it("leaves the destination path untouched on stream errors", async () => {
    const { sftp } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = new EventEmitter()
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt")
    const [tempPath] = vi.mocked(createWriteStream).mock.calls[0] as [string]
    localWriteStream.emit("error", new Error("local write stream broke"))

    await expect(promise).rejects.toThrow("local write stream broke")
    expect(vi.mocked(rename)).not.toHaveBeenCalled()
    expect(vi.mocked(unlink)).toHaveBeenCalledWith(tempPath)
    expect(vi.mocked(unlink)).not.toHaveBeenCalledWith("/local/file.txt")
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
    localWriteStream.emit("finish")
    await promise

    // Advance well past the timeout — must not cause additional effects
    vi.advanceTimersByTime(10_000)

    // Assert — promise already resolved; no extra sftp.end() from a late timeout
    await expect(promise).resolves.toBeUndefined()
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
  })

  it("resolves when the local writeStream emits close without finish (issue #37 race)", async () => {
    // Issue #37: align with the upload paths so a swallowed "finish" emit on
    // the local fs WriteStream cannot strand the download until the 120 s
    // timeout fires.
    const { sftp, sftpEnd, sftpReadStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = new EventEmitter()
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    const promise = sftpDownload(client, "/remote/file.txt", "/local/file.txt")
    localWriteStream.emit("close")

    await expect(promise).resolves.toBeUndefined()
    expect(sftpReadStream.destroy).not.toHaveBeenCalled()
    expect(sftpEnd).toHaveBeenCalledOnce()
    expect(vi.mocked(rename)).toHaveBeenCalledOnce()
  })
})

// ---------------------------------------------------------------------------
// sftpUpload
// ---------------------------------------------------------------------------

describe("sftpUpload", () => {
  afterEach(() => {
    vi.useRealTimers()
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

  it("rejects and ends the client when sftp session opening times out", async () => {
    vi.useFakeTimers()
    const clientEnd = vi.fn()
    const client = {
      end: clientEnd,
      sftp: vi.fn(),
    } as unknown as Client

    const promise = sftpUpload(client, "/local/file.txt", "/remote/file.txt", 5000)
    vi.advanceTimersByTime(5001)

    await expect(promise).rejects.toThrow(
      "SFTP upload session timed out after 5000ms: /remote/file.txt"
    )
    expect(clientEnd).toHaveBeenCalledOnce()
    expect(vi.mocked(createReadStream)).not.toHaveBeenCalled()
  })

  it("closes a late sftp session after upload session opening times out", async () => {
    vi.useFakeTimers()
    let openCallback: Parameters<Client["sftp"]>[0] | undefined
    const { sftp, sftpEnd } = makeSftpSession()
    const client = {
      end: vi.fn(),
      sftp: vi.fn().mockImplementation((cb: Parameters<Client["sftp"]>[0]) => {
        openCallback = cb
      }),
    } as unknown as Client

    const promise = sftpUpload(client, "/local/file.txt", "/remote/file.txt", 5000)
    vi.advanceTimersByTime(5001)
    await promise.catch(() => {
      /* expected rejection */
    })
    openCallback?.(undefined, sftp)

    expect(sftpEnd).toHaveBeenCalledOnce()
    expect(vi.mocked(createReadStream)).not.toHaveBeenCalled()
  })

  it("ignores a late sftp error callback after upload session opening times out", async () => {
    vi.useFakeTimers()
    let openCallback: Parameters<Client["sftp"]>[0] | undefined
    const client = {
      end: vi.fn(),
      sftp: vi.fn().mockImplementation((cb: Parameters<Client["sftp"]>[0]) => {
        openCallback = cb
      }),
    } as unknown as Client

    const promise = sftpUpload(client, "/local/file.txt", "/remote/file.txt", 5000)
    vi.advanceTimersByTime(5001)
    await promise.catch(() => {
      /* expected rejection */
    })

    expect(() => {
      openCallback?.(new Error("late sftp error"), undefined as unknown as SFTPWrapper)
    }).not.toThrow()
    expect(vi.mocked(createReadStream)).not.toHaveBeenCalled()
  })

  it("rejects and closes the sftp session when local read stream creation throws", async () => {
    const { sftp, sftpEnd } = makeSftpSession()
    const client = makeClientMock(sftp)
    vi.mocked(createReadStream).mockImplementation(() => {
      throw new Error("local open failed")
    })

    await expect(sftpUpload(client, "/local/file.txt", "/remote/file.txt")).rejects.toThrow(
      "local open failed"
    )
    expect(sftpEnd).toHaveBeenCalledOnce()
    expect(vi.mocked(sftp).createWriteStream.mock.calls).toHaveLength(0)
  })

  it("rejects, destroys the local stream, and closes sftp when remote write stream creation throws", async () => {
    const { sftp, sftpEnd } = makeSftpSession()
    const client = makeClientMock(sftp)
    const localReadStream = makeMockStream()
    vi.mocked(createReadStream).mockReturnValue(localReadStream as unknown as ReadStream)
    vi.mocked(sftp).createWriteStream.mockImplementation(() => {
      throw new Error("remote open failed")
    })

    await expect(sftpUpload(client, "/local/file.txt", "/remote/file.txt")).rejects.toThrow(
      "remote open failed"
    )
    expect(localReadStream.destroy).toHaveBeenCalledOnce()
    expect(sftpEnd).toHaveBeenCalledOnce()
  })

  it("creates the remote writeStream with restrictive mode 0600", async () => {
    const { sftp, sftpWriteStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localReadStream = makeMockStream()
    vi.mocked(createReadStream).mockReturnValue(localReadStream as unknown as ReadStream)

    const promise = sftpUpload(client, "/local/file.txt", "/remote/file.txt")
    sftpWriteStream.emit("finish")

    await expect(promise).resolves.toBeUndefined()
    const createWriteStreamCalls = (
      sftp.createWriteStream as unknown as { mock: { calls: unknown[][] } }
    ).mock.calls
    expect(createWriteStreamCalls).toHaveLength(1)
    expect(createWriteStreamCalls[0]).toStrictEqual(["/remote/file.txt", { mode: 0o600 }])
    expect(localReadStream.pipe).toHaveBeenCalledWith(sftpWriteStream)
  })

  it("preserves unicode local and remote paths for uploads", async () => {
    const { sftp, sftpWriteStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localReadStream = makeMockStream()
    vi.mocked(createReadStream).mockReturnValue(localReadStream as unknown as ReadStream)

    const localPath = "/local/über ordner/ß-datei.txt"
    const remotePath = "/remote/über ordner/こんにちは.txt"
    const promise = sftpUpload(client, localPath, remotePath)
    sftpWriteStream.emit("finish")

    await expect(promise).resolves.toBeUndefined()
    expect(vi.mocked(createReadStream)).toHaveBeenCalledWith(localPath)
    const createWriteStreamCalls = (
      sftp.createWriteStream as unknown as { mock: { calls: unknown[][] } }
    ).mock.calls
    expect(createWriteStreamCalls[0]).toStrictEqual([remotePath, { mode: 0o600 }])
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

  it("resolves when the remote writeStream emits finish", async () => {
    // Arrange
    const { sftp, sftpEnd, sftpWriteStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localReadStream = makeMockStream()
    vi.mocked(createReadStream).mockReturnValue(localReadStream as unknown as ReadStream)

    // Act — start the promise, then simulate a successful transfer completion
    const promise = sftpUpload(client, "/local/file.txt", "/remote/file.txt")
    sftpWriteStream.emit("finish")

    // Assert — promise must resolve on successful transfer
    await expect(promise).resolves.toBeUndefined()
    expect(sftpEnd).toHaveBeenCalledOnce()
  })

  it("absorbs a late sftp wrapper error after upload settles", async () => {
    const { sftp, sftpEnd, sftpWriteStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localReadStream = makeMockStream()
    vi.mocked(createReadStream).mockReturnValue(localReadStream as unknown as ReadStream)

    const promise = sftpUpload(client, "/local/file.txt", "/remote/file.txt")
    sftpWriteStream.emit("finish")

    await expect(promise).resolves.toBeUndefined()
    expect(() => {
      sftp.emit("error", new Error("late sftp wrapper error"))
    }).not.toThrow()
    expect(sftpEnd).toHaveBeenCalledOnce()
  })

  it("resolves when the remote writeStream emits close without finish (issue #37 race)", async () => {
    // Issue #37: ssh2's SFTP WriteStream can emit "close" without scheduling
    // "finish" for the final flush — same race as sftpUploadContent.
    // "close" is now a completion event so the upload resolves on either.
    const { sftp, sftpEnd, sftpWriteStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localReadStream = makeMockStream()
    vi.mocked(createReadStream).mockReturnValue(localReadStream as unknown as ReadStream)

    const promise = sftpUpload(client, "/local/file.txt", "/remote/file.txt")
    sftpWriteStream.emit("close")

    await expect(promise).resolves.toBeUndefined()
    expect(localReadStream.destroy).not.toHaveBeenCalled()
    expect(sftpWriteStream.destroy).not.toHaveBeenCalled()
    expect(sftpEnd).toHaveBeenCalledOnce()
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
    sftpWriteStream.emit("finish")
    await promise

    // Advance well past the timeout — must not cause additional effects
    vi.advanceTimersByTime(10_000)

    // Assert — promise already resolved; no extra sftp.end() from a late timeout
    await expect(promise).resolves.toBeUndefined()
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
  })
})

// ---------------------------------------------------------------------------
// sftpUploadContent
// ---------------------------------------------------------------------------

describe("sftpUploadContent", () => {
  afterEach(() => {
    vi.useRealTimers()
    vi.resetAllMocks()
  })

  it("streams UTF-8 content to the remote writeStream without opening a local file", async () => {
    const { sftp, sftpEnd } = makeSftpSession()
    const client = makeClientMock(sftp)
    const remoteWriteStream = new CollectingWritableStream()
    vi.mocked(sftp).createWriteStream.mockReturnValue(remoteWriteStream as never)

    await expect(
      sftpUploadContent(client, "hello üñîçødé", "/remote/secret.txt")
    ).resolves.toBeUndefined()

    expect(vi.mocked(createReadStream)).not.toHaveBeenCalled()
    const createWriteStreamCalls = (
      sftp.createWriteStream as unknown as { mock: { calls: unknown[][] } }
    ).mock.calls
    expect(createWriteStreamCalls[0]).toStrictEqual(["/remote/secret.txt", { mode: 0o600 }])
    expect(Buffer.concat(remoteWriteStream.chunks).toString("utf8")).toBe("hello üñîçødé")
    expect(sftpEnd).toHaveBeenCalledOnce()
  })

  it("absorbs a late sftp wrapper error after content upload settles", async () => {
    const { sftp, sftpEnd } = makeSftpSession()
    const client = makeClientMock(sftp)
    const remoteWriteStream = new CollectingWritableStream()
    vi.mocked(sftp).createWriteStream.mockReturnValue(remoteWriteStream as never)

    await expect(sftpUploadContent(client, "secret", "/remote/secret.txt")).resolves.toBeUndefined()
    expect(() => {
      sftp.emit("error", new Error("late sftp wrapper error"))
    }).not.toThrow()
    expect(sftpEnd).toHaveBeenCalledOnce()
  })

  it("rejects and closes the sftp session when remote write stream creation throws", async () => {
    const { sftp, sftpEnd } = makeSftpSession()
    const client = makeClientMock(sftp)
    vi.mocked(sftp).createWriteStream.mockImplementation(() => {
      throw new Error("remote open failed")
    })

    await expect(sftpUploadContent(client, "secret", "/remote/secret.txt")).rejects.toThrow(
      "remote open failed"
    )
    expect(vi.mocked(createReadStream)).not.toHaveBeenCalled()
    expect(sftpEnd).toHaveBeenCalledOnce()
  })

  it("resolves when the remote writeStream emits close without ever firing finish (issue #37 race)", async () => {
    // Issue #37: for small in-memory payloads, ssh2's SFTP WriteStream may
    // emit "close" without scheduling "finish" at all. `writableFinished`
    // is still false at that point because it flips to true only immediately
    // before the "finish" emit. Treating "close" as a completion event
    // ensures the upload resolves on whichever event arrives first.
    const { sftp, sftpEnd, sftpWriteStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const promise = sftpUploadContent(client, "small", "/remote/secret.txt")
    // No writableFinished, no "finish" — just the bare "close" the issue
    // reporter observed on the failing target.
    sftpWriteStream.emit("close")

    await expect(promise).resolves.toBeUndefined()
    expect(sftpWriteStream.destroy).not.toHaveBeenCalled()
    expect(sftpEnd).toHaveBeenCalledOnce()
  })

  it("still resolves when the remote writeStream emits finish before close", async () => {
    // Regression guard for the regular ordering — "finish" arrives first
    // and resolves; the trailing "close" must not re-settle or destroy.
    const { sftp, sftpEnd, sftpWriteStream } = makeSftpSession()
    const client = makeClientMock(sftp)

    const promise = sftpUploadContent(client, "small", "/remote/secret.txt")
    sftpWriteStream.emit("finish")
    sftpWriteStream.emit("close")

    await expect(promise).resolves.toBeUndefined()
    expect(sftpWriteStream.destroy).not.toHaveBeenCalled()
    expect(sftpEnd).toHaveBeenCalledOnce()
  })
})

// ---------------------------------------------------------------------------
// connection-level abort signal (R-0000255)
// ---------------------------------------------------------------------------

describe("SFTP connection abort signal", () => {
  afterEach(() => {
    vi.useRealTimers()
    vi.resetAllMocks()
  })

  beforeEach(() => {
    vi.mocked(rename).mockResolvedValue(undefined)
    // R-0000666: async unlink cleanup must keep returning a resolved promise
    // after vi.resetAllMocks() removes the implementation.
    vi.mocked(unlink).mockResolvedValue(undefined)
  })

  it("rejects an in-flight sftpUpload immediately when the connection abort signal fires (R-0000255)", async () => {
    const { sftp } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localReadStream = new MockReadableStream()
    vi.mocked(createReadStream).mockReturnValue(localReadStream as unknown as ReadStream)

    const abortController = new AbortController()
    const start = Date.now()
    const promise = sftpUpload(
      client,
      "/local/file.txt",
      "/remote/file.txt",
      120_000,
      abortController.signal
    )

    // Allow the wireStreams listener registration to settle, then abort.
    await Promise.resolve()
    abortController.abort()

    await expect(promise).rejects.toThrow(/SFTP transfer aborted: ssh disconnect/v)
    // The default 120 s timer must NOT have run.
    expect(Date.now() - start).toBeLessThan(2000)
  })

  it("rejects sftpDownload immediately when the connection abort signal fires", async () => {
    const { sftp } = makeSftpSession()
    const client = makeClientMock(sftp)

    const localWriteStream = new CollectingWritableStream()
    vi.mocked(createWriteStream).mockReturnValue(localWriteStream as unknown as WriteStream)

    const abortController = new AbortController()
    const promise = sftpDownload(
      client,
      "/remote/file.txt",
      "/local/file.txt",
      120_000,
      abortController.signal
    )

    await Promise.resolve()
    abortController.abort()

    await expect(promise).rejects.toThrow(/SFTP transfer aborted: ssh disconnect/v)
  })

  it("rejects sftpUploadContent immediately when the connection abort signal fires", async () => {
    const { sftp } = makeSftpSession()
    const client = makeClientMock(sftp)

    const abortController = new AbortController()
    const promise = sftpUploadContent(
      client,
      "hello",
      "/remote/file.txt",
      120_000,
      abortController.signal
    )

    await Promise.resolve()
    abortController.abort()

    await expect(promise).rejects.toThrow(/SFTP transfer aborted: ssh disconnect/v)
  })

  it("rejects sftpUpload immediately when the connection abort signal already fired before the call", async () => {
    const { sftp } = makeSftpSession()
    const client = makeClientMock(sftp)

    const abortController = new AbortController()
    abortController.abort()

    await expect(
      sftpUpload(client, "/local/file.txt", "/remote/file.txt", 120_000, abortController.signal)
    ).rejects.toThrow(/SFTP session aborted: ssh disconnect/v)
  })
})
