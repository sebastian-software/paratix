import type { Client, SFTPWrapper } from "ssh2"

import { EventEmitter } from "node:events"
import { createReadStream, createWriteStream, type ReadStream, type WriteStream } from "node:fs"
import { afterEach, describe, expect, it, vi } from "vitest"

import { sftpDownload, sftpUpload } from "../src/sftp.js"

// vi.mock is hoisted to the top of the file by vitest before any imports are
// evaluated, so the module under test receives the mocked version.
vi.mock("node:fs", () => ({
  createReadStream: vi.fn(),
  createWriteStream: vi.fn(),
}))

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Minimal stream mock that supports piping and emitting error events. */
type SftpMockStream = { pipe: ReturnType<typeof vi.fn> } & EventEmitter

class MockReadableStream extends EventEmitter {
  public pipe = vi.fn()
}

function makeMockStream(): SftpMockStream {
  return new MockReadableStream() as SftpMockStream
}

function makeSftpSession() {
  const sftpReadStream = makeMockStream()
  const sftpWriteStream = new EventEmitter()
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
})
