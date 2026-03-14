import type { Client, SFTPWrapper } from "ssh2"

import { EventEmitter } from "node:events"
import { unlinkSync, writeFileSync } from "node:fs"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { sftpUpload } from "../src/sftp.js"
import { SshConnectionImpl } from "../src/ssh.js"

// vi.mock is hoisted to the top of the file by vitest before any imports are
// evaluated, so the module under test receives the mocked version.
vi.mock("node:fs", () => ({
  readFileSync: vi.fn().mockReturnValue(""),
  unlinkSync: vi.fn(),
  writeFileSync: vi.fn(),
}))

vi.mock("../src/sftp.js", () => ({
  sftpUpload: vi.fn(),
}))

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SFTP_WRITE_THRESHOLD = 65_536

function makeSmallContent(): string {
  return "a".repeat(SFTP_WRITE_THRESHOLD)
}

function makeLargeContent(): string {
  return "a".repeat(SFTP_WRITE_THRESHOLD + 1)
}

type StreamWithStderr = { stderr: EventEmitter } & EventEmitter

type ExecCallback = (err: Error | undefined, stream: StreamWithStderr) => void

function makeStream(): StreamWithStderr {
  const stream = new EventEmitter() as StreamWithStderr
  stream.stderr = new EventEmitter()
  return stream
}

function makeExecSpy(mktempResult: string): ReturnType<typeof vi.fn> {
  return vi.fn().mockImplementation((cmd: string, cb: ExecCallback) => {
    const stream = makeStream()
    cb(undefined, stream)
    if (cmd.includes("mktemp")) {
      stream.emit("data", Buffer.from(mktempResult))
    }
    stream.emit("close", 0)
  })
}

function makeClientWithExecSpy(execSpy: ReturnType<typeof vi.fn>): Client {
  return {
    exec: execSpy,
    sftp: vi.fn().mockImplementation((cb: Parameters<Client["sftp"]>[0]) => {
      cb(undefined, {} as SFTPWrapper)
    }),
  } as unknown as Client
}

function makeSimpleClient(): Client {
  return {
    exec: vi.fn().mockImplementation((_cmd: string, cb: ExecCallback) => {
      const stream = makeStream()
      cb(undefined, stream)
      stream.emit("close", 0)
    }),
    sftp: vi.fn().mockImplementation((cb: Parameters<Client["sftp"]>[0]) => {
      cb(undefined, {} as SFTPWrapper)
    }),
  } as unknown as Client
}

function makeConnectedSsh(client: Client): SshConnectionImpl {
  const config = {
    ports: [22],
    privateKey: "/dev/null",
    user: "root",
  }
  const ssh = new SshConnectionImpl("1.2.3.4", config)
  // Inject the mock client to avoid a real TCP connection.
  ;(ssh as unknown as Record<string, unknown>).client = client
  return ssh
}

// ---------------------------------------------------------------------------
// Tests — small content (≤ 64 KB)
// ---------------------------------------------------------------------------

describe("SshConnectionImpl.writeFile — small content (≤ 64 KB)", () => {
  afterEach(() => {
    vi.resetAllMocks()
  })

  it("uses printf/tee via exec and never calls sftpUpload", async () => {
    // Arrange
    const execSpy = vi.fn().mockImplementation((_cmd: string, cb: ExecCallback) => {
      const stream = makeStream()
      cb(undefined, stream)
      stream.emit("close", 0)
    })
    const client = makeClientWithExecSpy(execSpy)
    const ssh = makeConnectedSsh(client)
    const content = makeSmallContent()

    // Act
    await ssh.writeFile("/etc/config", content)

    // Assert: exec was called once with printf/tee pattern
    expect(execSpy).toHaveBeenCalledOnce()
    const [cmd] = execSpy.mock.calls[0] as [string, ...unknown[]]
    expect(cmd).toContain("printf '%s'")
    expect(cmd).toContain("tee")
    expect(cmd).toContain("/etc/config")

    // SFTP path must not be used
    expect(vi.mocked(sftpUpload)).not.toHaveBeenCalled()
    expect(vi.mocked(writeFileSync)).not.toHaveBeenCalled()
    expect(vi.mocked(unlinkSync)).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// Tests — large content (> 64 KB)
// ---------------------------------------------------------------------------

describe("SshConnectionImpl.writeFile — large content (> 64 KB)", () => {
  let execSpy: ReturnType<typeof vi.fn>

  beforeEach(() => {
    execSpy = makeExecSpy("/tmp/paratix-write.ABCDEF")
    vi.mocked(sftpUpload).mockResolvedValue()
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  it("creates a local tmp file via writeFileSync", async () => {
    // Arrange
    const client = makeClientWithExecSpy(execSpy)
    const ssh = makeConnectedSsh(client)
    const content = makeLargeContent()

    // Act
    await ssh.writeFile("/etc/large-config", content)

    // Assert
    expect(vi.mocked(writeFileSync)).toHaveBeenCalledOnce()
    const [localPath, writtenContent] = vi.mocked(writeFileSync).mock.calls[0] as [string, string]
    expect(localPath).toMatch(/paratix-write-/v)
    expect(writtenContent).toBe(content)
  })

  it("calls sftpUpload with the local tmp file and the remote tmp path", async () => {
    // Arrange
    const client = makeClientWithExecSpy(execSpy)
    const ssh = makeConnectedSsh(client)
    const content = makeLargeContent()

    // Act
    await ssh.writeFile("/etc/large-config", content)

    // Assert
    expect(vi.mocked(sftpUpload)).toHaveBeenCalledOnce()
    const [, localPath, remoteTmpPath] = vi.mocked(sftpUpload).mock.calls[0] as [
      unknown,
      string,
      string,
    ]
    expect(localPath).toMatch(/paratix-write-/v)
    expect(remoteTmpPath).toBe("/tmp/paratix-write.ABCDEF")
  })

  it("moves the remote tmp file to the final destination via mv", async () => {
    // Arrange
    const client = makeClientWithExecSpy(execSpy)
    const ssh = makeConnectedSsh(client)
    const content = makeLargeContent()

    // Act
    await ssh.writeFile("/etc/large-config", content)

    // Assert: one of the exec calls must be the mv command
    const calls = execSpy.mock.calls as Array<[string, ...unknown[]]>
    const mvCall = calls.find(([cmd]) => cmd.includes("mv"))
    expect(mvCall).toBeDefined()
    const [mvCmd] = mvCall!
    expect(mvCmd).toContain("/tmp/paratix-write.ABCDEF")
    expect(mvCmd).toContain("/etc/large-config")
  })

  it("removes the local tmp file after a successful upload (finally block)", async () => {
    // Arrange
    const client = makeClientWithExecSpy(execSpy)
    const ssh = makeConnectedSsh(client)
    const content = makeLargeContent()

    // Act
    await ssh.writeFile("/etc/large-config", content)

    // Assert: unlinkSync was called with the same path written by writeFileSync
    expect(vi.mocked(unlinkSync)).toHaveBeenCalledOnce()
    const [unlinkedPath] = vi.mocked(unlinkSync).mock.calls[0] as [string]
    const [writtenPath] = vi.mocked(writeFileSync).mock.calls[0] as [string, ...unknown[]]
    expect(unlinkedPath).toBe(writtenPath)
  })

  it("removes the local tmp file even when sftpUpload throws (finally block)", async () => {
    // Arrange
    vi.mocked(sftpUpload).mockRejectedValue(new Error("SFTP transfer failed"))
    const client = makeSimpleClient()
    const ssh = makeConnectedSsh(client)
    const content = makeLargeContent()

    // Act + Assert: the error propagates
    await expect(ssh.writeFile("/etc/large-config", content)).rejects.toThrow(
      "SFTP transfer failed"
    )

    // Cleanup must still happen despite the error
    expect(vi.mocked(unlinkSync)).toHaveBeenCalledOnce()
  })
})
