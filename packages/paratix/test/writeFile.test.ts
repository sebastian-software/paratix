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

function makeSmallContent(): string {
  return "hello world"
}

function makeLargeContent(): string {
  return "a".repeat(100_000)
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
    exec: vi.fn().mockImplementation((cmd: string, cb: ExecCallback) => {
      const stream = makeStream()
      cb(undefined, stream)
      if (cmd.includes("mktemp")) {
        stream.emit("data", Buffer.from("/tmp/paratix-write.SIMPLE"))
      }
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
// Tests — small content (atomic write via SFTP, same as large content)
// ---------------------------------------------------------------------------

describe("SshConnectionImpl.writeFile — small content", () => {
  let execSpy: ReturnType<typeof vi.fn>

  beforeEach(() => {
    execSpy = makeExecSpy("/tmp/paratix-write.SMALL")
    vi.mocked(sftpUpload).mockResolvedValue()
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  it("uses atomic SFTP path (write-to-temp + mv) even for small content", async () => {
    // Arrange
    const client = makeClientWithExecSpy(execSpy)
    const ssh = makeConnectedSsh(client)
    const content = makeSmallContent()

    // Act
    await ssh.writeFile("/etc/config", content)

    // Assert: SFTP path was used — writeFileSync creates local temp, sftpUpload transfers
    expect(vi.mocked(sftpUpload)).toHaveBeenCalledOnce()
    expect(vi.mocked(writeFileSync)).toHaveBeenCalledOnce()

    // exec calls: mktemp, mv, rm -f
    const calls = execSpy.mock.calls as Array<[string, ...unknown[]]>
    const executedCommands = calls.map(([cmd]) => cmd)
    expect(executedCommands.some((cmd) => cmd.includes("mktemp"))).toBe(true)
    expect(executedCommands.some((cmd) => cmd.includes("mv"))).toBe(true)

    // printf/tee must NOT be used
    expect(executedCommands.some((cmd) => cmd.includes("printf"))).toBe(false)
    expect(executedCommands.some((cmd) => cmd.includes("tee"))).toBe(false)
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

  // ---------------------------------------------------------------------------
  // Regression: local temp file must be created with mode 0o600 (not world-readable)
  // ---------------------------------------------------------------------------

  it("creates the local tmp file with mode 0o600 (regression: was world-readable without mode option)", async () => {
    // Root cause: writeFileSync(localTemporary, content) was called without a
    // mode option, resulting in the default 0o666 (world-readable after umask).
    // Fix: writeFileSync(localTemporary, content, { mode: 0o600 }) ensures the
    // temp file is owner-only, protecting sensitive content during the upload.
    const client = makeClientWithExecSpy(execSpy)
    const ssh = makeConnectedSsh(client)
    const content = makeLargeContent()

    // Act
    await ssh.writeFile("/etc/large-config", content)

    // Assert: third argument to writeFileSync must include mode 0o600
    expect(vi.mocked(writeFileSync)).toHaveBeenCalledOnce()
    const writeCall = vi.mocked(writeFileSync).mock.calls[0] as [string, string, { mode: number }]
    const options = writeCall[2]
    expect(options).toMatchObject({ mode: 0o600 })
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

  // ---------------------------------------------------------------------------
  // Regression: remote tmp file cleanup after sftpUpload failure
  // ---------------------------------------------------------------------------

  it("calls rm -f for the remote tmp file when sftpUpload throws (best-effort cleanup)", async () => {
    // Arrange
    const remoteTmpPath = "/tmp/paratix-write.CLEANUP"
    vi.mocked(sftpUpload).mockRejectedValue(new Error("SFTP transfer failed"))
    const remoteCleanupSpy = makeExecSpy(remoteTmpPath)
    const client = makeClientWithExecSpy(remoteCleanupSpy)
    const ssh = makeConnectedSsh(client)
    const content = makeLargeContent()

    // Act + Assert: the original sftpUpload error propagates
    await expect(ssh.writeFile("/etc/large-config", content)).rejects.toThrow(
      "SFTP transfer failed"
    )

    // Assert: exec must have been called with rm -f for the remote tmp path.
    // The rm -f is the last exec call (after mktemp and the failed sftpUpload).
    const calls = remoteCleanupSpy.mock.calls as Array<[string, ...unknown[]]>
    const executedCommands = calls.map(([cmd]) => cmd)
    expect(executedCommands).toStrictEqual(
      expect.arrayContaining([expect.stringContaining(`rm -f '${remoteTmpPath}'`)])
    )
  })

  it("swallows an error thrown by the remote rm -f cleanup (best-effort)", async () => {
    // Arrange: sftpUpload succeeds, but rm -f in the finally block throws
    const remoteTmpPath = "/tmp/paratix-write.CLEANUP2"

    // exec spy: mktemp returns the remote tmp path, mv succeeds, rm -f fails
    const cleanupExecSpy = vi
      .fn()
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // First call is always mktemp (via output()) — emit the remote tmp path
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from(remoteTmpPath))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // Second call is mv — succeeds
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // Third call is rm -f — simulates a failure (e.g. permission denied)
        cb(new Error("rm -f failed unexpectedly"), makeStream())
      })

    const client = makeClientWithExecSpy(cleanupExecSpy)
    const ssh = makeConnectedSsh(client)
    const content = makeLargeContent()

    // Act + Assert: writeFile must resolve successfully despite the rm -f failure
    await expect(ssh.writeFile("/etc/large-config", content)).resolves.toBeUndefined()
  })

  // ---------------------------------------------------------------------------
  // Regression: cleanup error messages must not expose sudo passwords
  // ---------------------------------------------------------------------------

  it("masks sudo password in cleanup error message for writeFile", async () => {
    // Arrange
    const sudoPassword = "mysecretpass"
    const remoteTmpPath = "/tmp/paratix-write.MASKSECRET"

    // exec spy: mktemp succeeds, mv succeeds, rm -f fails with an error that
    // contains the sudo password in plain text (simulates a verbose error message)
    const cleanupExecSpy = vi
      .fn()
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // First call: mktemp — returns the remote tmp path
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from(remoteTmpPath))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // Second call: mv — succeeds
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // Third call: rm -f — fails with an error whose message contains the password
        cb(
          new Error(`permission denied: echo ${sudoPassword} | sudo rm -f ${remoteTmpPath}`),
          makeStream()
        )
      })

    const client = makeClientWithExecSpy(cleanupExecSpy)
    const ssh = makeConnectedSsh(client)
    ;(ssh as unknown as Record<string, unknown>).cachedSudoPassword = Buffer.from(sudoPassword)
    const content = makeLargeContent()

    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true)

    // Act: writeFile must resolve despite the rm -f failure
    await expect(ssh.writeFile("/etc/large-config", content)).resolves.toBeUndefined()

    // Assert: stderr must not contain the plain-text password
    const stderrOutput = stderrSpy.mock.calls.map((args) => String(args[0])).join("")
    expect(stderrOutput).not.toContain(sudoPassword)
    expect(stderrOutput).toContain("[REDACTED]")

    stderrSpy.mockRestore()
  })
})

// ---------------------------------------------------------------------------
// Tests — uploadFile cleanup error secret masking
// ---------------------------------------------------------------------------

describe("SshConnectionImpl.uploadFile — cleanup error secret masking", () => {
  afterEach(() => {
    vi.resetAllMocks()
  })

  it("masks sudo password in cleanup error message for uploadFile", async () => {
    // Arrange
    const sudoPassword = "upload-secret-pw"
    const remoteTmpPath = "/tmp/paratix-upload.MASKSECRET"

    // exec spy: mktemp succeeds, mv succeeds, rm -f fails with an error that
    // contains the sudo password in plain text (simulates a verbose error message)
    const cleanupExecSpy = vi
      .fn()
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // First call: mktemp — returns the remote tmp path
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from(remoteTmpPath))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // Second call: mv — succeeds
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // Third call: rm -f — fails with an error whose message contains the password
        cb(
          new Error(`permission denied: echo ${sudoPassword} | sudo rm -f ${remoteTmpPath}`),
          makeStream()
        )
      })

    vi.mocked(sftpUpload).mockResolvedValue()

    const client = makeClientWithExecSpy(cleanupExecSpy)
    const ssh = makeConnectedSsh(client)
    ;(ssh as unknown as Record<string, unknown>).cachedSudoPassword = Buffer.from(sudoPassword)

    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true)

    // Act: uploadFile must resolve despite the rm -f failure
    await expect(ssh.uploadFile("/local/path/file.txt", "/etc/file.txt")).resolves.toBeUndefined()

    // Assert: stderr must not contain the plain-text password
    const stderrOutput = stderrSpy.mock.calls.map((args) => String(args[0])).join("")
    expect(stderrOutput).not.toContain(sudoPassword)
    expect(stderrOutput).toContain("[REDACTED]")

    stderrSpy.mockRestore()
  })
})
