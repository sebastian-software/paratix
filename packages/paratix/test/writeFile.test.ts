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

  // ---------------------------------------------------------------------------
  // Security: local tmp filename must not be predictable (Date.now()-based)
  //
  // BUG: ssh.ts line 230 uses `paratix-write-${Date.now()}` which produces a
  // predictable, timestamp-based filename. An attacker who knows the approximate
  // time a file operation will occur can pre-create the path as a symlink and
  // redirect the write to an arbitrary location (symlink attack / TOCTOU).
  //
  // This test MUST FAIL until the bug is fixed by replacing Date.now() with a
  // cryptographically random suffix (e.g. crypto.randomUUID()).
  // ---------------------------------------------------------------------------

  it("uses a cryptographically random suffix (not a timestamp) for the local tmp filename", async () => {
    // Arrange — freeze time so that Date.now() always returns the same value.
    // If the implementation uses Date.now(), two consecutive writeFile calls will
    // produce the exact same filename, proving the name is predictable (symlink
    // attack / TOCTOU vulnerability).
    vi.useFakeTimers()
    vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"))

    const content = makeLargeContent()

    // First call — capture the generated local tmp path immediately afterwards.
    const client1 = makeClientWithExecSpy(execSpy)
    const ssh1 = makeConnectedSsh(client1)
    await ssh1.writeFile("/etc/large-config", content)
    const [firstPath] = vi.mocked(writeFileSync).mock.calls[0] as [string, ...unknown[]]

    // Reset only the call history (not the mock implementations) so the second
    // call can be observed independently without reconstructing the entire spy.
    vi.mocked(writeFileSync).mockClear()
    vi.mocked(sftpUpload).mockClear()
    vi.mocked(sftpUpload).mockResolvedValue()

    // Second call — time is still frozen at the same millisecond.
    const execSpy2 = makeExecSpy("/tmp/paratix-write.ABCDEF")
    const client2 = makeClientWithExecSpy(execSpy2)
    const ssh2 = makeConnectedSsh(client2)
    await ssh2.writeFile("/etc/large-config", content)
    const [secondPath] = vi.mocked(writeFileSync).mock.calls[0] as [string, ...unknown[]]

    // The suffix after "paratix-write-" must be a UUID, not a decimal timestamp.
    // UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (RFC 4122)
    const uuidSuffixPattern =
      /paratix-write-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iv

    expect(firstPath).toMatch(uuidSuffixPattern)
    expect(secondPath).toMatch(uuidSuffixPattern)

    // Even with time frozen, two calls must produce distinct names.
    expect(firstPath).not.toBe(secondPath)
  })
})
