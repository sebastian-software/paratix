import type { Client, SFTPWrapper } from "ssh2"

import { EventEmitter } from "node:events"
import { writeFileSync } from "node:fs"
import { stat } from "node:fs/promises"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { sftpUpload, sftpUploadContent } from "../src/sftp.js"
import { SshConnectionImpl } from "../src/ssh.js"

// vi.mock is hoisted to the top of the file by vitest before any imports are
// evaluated, so the module under test receives the mocked version.
vi.mock("node:fs", () => ({
  readFileSync: vi.fn().mockReturnValue(""),
  writeFileSync: vi.fn(),
}))

vi.mock("node:fs/promises", () => ({
  stat: vi.fn().mockResolvedValue({ size: 11 }),
}))

vi.mock("../src/sftp.js", () => ({
  sftpUpload: vi.fn(),
  sftpUploadContent: vi.fn(),
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

function isBase64FallbackCommand(command: string, tmpPath: string): boolean {
  return command.includes("base64 -d") && command.includes(tmpPath)
}

type StreamWithStderr = { stderr: EventEmitter } & EventEmitter

type ExecCallback = (err: Error | undefined, stream: StreamWithStderr) => void

function makeStream(): StreamWithStderr {
  const stream = new EventEmitter() as StreamWithStderr
  stream.stderr = new EventEmitter()
  return stream
}

// R-0000141: extract the literal directory argument that the dirname-symlink
// probe passed to `realpath -m --`. The probe shape is:
//     realpath -m -- '<dir>' 2>/dev/null || printf '%s' '<dir>'
// Mock helpers must echo `<dir>` back so the equality check passes.
const REALPATH_DIRECTORY_PATTERN = /realpath -m -- '(?<directory>[^']*)'/v
function extractRealpathDirectory(command: string): string {
  return REALPATH_DIRECTORY_PATTERN.exec(command)?.groups?.directory ?? ""
}

function isContentTransportPrintf(command: string): boolean {
  return command.includes("printf") && !command.includes("realpath")
}

// R-0000141: shared mock handler for the realpath dirname-symlink probe —
// echoes the literal directory back to the caller so the equality check in
// assertDirnameHasNoSymlinkComponent passes.
function realpathProbeHandler(cmd: string, cb: ExecCallback): void {
  const stream = makeStream()
  cb(undefined, stream)
  stream.emit("data", Buffer.from(extractRealpathDirectory(cmd)))
  stream.emit("close", 0)
}

function makeDiskCheckExecSpy(prefix: string, dfOutput: string): ReturnType<typeof vi.fn> {
  let counter = 0
  return vi.fn().mockImplementation((cmd: string, cb: ExecCallback) => {
    const stream = makeStream()
    cb(undefined, stream)
    const realpathDirectory = extractRealpathDirectory(cmd)
    if (realpathDirectory !== "") {
      stream.emit("data", Buffer.from(realpathDirectory))
    } else if (cmd.includes("mktemp")) {
      counter++
      stream.emit("data", Buffer.from(`/etc/systemd/system/paratix-write.${prefix}${counter}`))
    } else if (cmd.includes("stat -c '%s'")) {
      stream.emit("data", Buffer.from("0"))
    } else if (cmd.includes("df -P")) {
      stream.emit("data", Buffer.from(dfOutput))
    }
    stream.emit("close", 0)
  })
}

function makeExecSpy(mktempResult: string, verifiedSize = 100_000): ReturnType<typeof vi.fn> {
  return vi.fn().mockImplementation((cmd: string, cb: ExecCallback) => {
    const stream = makeStream()
    cb(undefined, stream)
    const realpathDirectory = extractRealpathDirectory(cmd)
    if (realpathDirectory !== "") {
      stream.emit("data", Buffer.from(realpathDirectory))
    } else if (cmd.includes("mktemp")) {
      stream.emit("data", Buffer.from(mktempResult))
    } else if (cmd.includes("stat -c '%s'")) {
      stream.emit("data", Buffer.from(String(verifiedSize)))
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
      const realpathDirectory = extractRealpathDirectory(cmd)
      if (realpathDirectory !== "") {
        stream.emit("data", Buffer.from(realpathDirectory))
      } else if (cmd.includes("mktemp")) {
        stream.emit("data", Buffer.from("/etc/paratix-write.SIMPLE"))
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
    execSpy = makeExecSpy("/etc/paratix-write.SMALL", 11)
    vi.mocked(sftpUploadContent).mockResolvedValue()
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
    await ssh.writeFile("/etc/config", content, { mode: "0600" })

    // Assert: SFTP path was used without creating a local content file.
    expect(vi.mocked(sftpUploadContent)).toHaveBeenCalledOnce()
    expect(vi.mocked(writeFileSync)).not.toHaveBeenCalled()

    // exec calls: mktemp, mv, rm -f
    const calls = execSpy.mock.calls as Array<[string, ...unknown[]]>
    const executedCommands = calls.map(([cmd]) => cmd)
    expect(executedCommands.some((cmd) => cmd.includes("mktemp"))).toBe(true)
    expect(executedCommands.some((cmd) => cmd.includes("mv"))).toBe(true)

    // printf/tee must NOT be used to transport content. The dirname-symlink
    // probe (R-0000141) uses `printf '%s'` only as a fallback for the
    // directory string when realpath is unavailable; that is not a content
    // transport pipeline.
    expect(executedCommands.some((cmd) => isContentTransportPrintf(cmd))).toBe(false)
    expect(executedCommands.some((cmd) => cmd.includes("tee"))).toBe(false)
  })

  it("throws a clear validation error when options.mode is missing instead of crashing with a TypeError", async () => {
    const client = makeClientWithExecSpy(execSpy)
    const ssh = makeConnectedSsh(client)
    const content = makeSmallContent()
    const unsafeSsh = ssh as unknown as {
      writeFile: (
        remotePath: string,
        fileContent: string,
        options?: { mode?: string }
      ) => Promise<void>
    }

    await expect(unsafeSsh.writeFile("/etc/config", content)).rejects.toThrow(
      '[ssh.writeFile: /etc/config] missing options.mode; pass { mode: "0644" } or another explicit file mode'
    )
    expect(vi.mocked(writeFileSync)).not.toHaveBeenCalled()
    expect(vi.mocked(sftpUpload)).not.toHaveBeenCalled()
    expect(vi.mocked(sftpUploadContent)).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// Tests — large content (> 64 KB)
// ---------------------------------------------------------------------------

describe("SshConnectionImpl.writeFile — large content (> 64 KB)", () => {
  let execSpy: ReturnType<typeof vi.fn>

  beforeEach(() => {
    execSpy = makeExecSpy("/etc/paratix-write.ABCDEF", 100_000)
    vi.mocked(sftpUploadContent).mockResolvedValue()
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  it("does not create a local content file via writeFileSync", async () => {
    // Arrange
    const client = makeClientWithExecSpy(execSpy)
    const ssh = makeConnectedSsh(client)
    const content = makeLargeContent()

    // Act
    await ssh.writeFile("/etc/large-config", content, { mode: "0600" })

    // Assert
    expect(vi.mocked(writeFileSync)).not.toHaveBeenCalled()
  })

  it("calls sftpUploadContent with the content and the remote tmp path", async () => {
    // Arrange
    const client = makeClientWithExecSpy(execSpy)
    const ssh = makeConnectedSsh(client)
    const content = makeLargeContent()

    // Act
    await ssh.writeFile("/etc/large-config", content, { mode: "0600" })

    // Assert
    expect(vi.mocked(sftpUploadContent)).toHaveBeenCalledOnce()
    const [, uploadedContent, remoteTmpPath] = vi.mocked(sftpUploadContent).mock.calls[0] as [
      unknown,
      string,
      string,
    ]
    expect(uploadedContent).toBe(content)
    expect(remoteTmpPath).toBe("/etc/paratix-write.ABCDEF")
  })

  it("moves the remote tmp file to the final destination via mv", async () => {
    // Arrange
    const client = makeClientWithExecSpy(execSpy)
    const ssh = makeConnectedSsh(client)
    const content = makeLargeContent()

    // Act
    await ssh.writeFile("/etc/large-config", content, { mode: "0600" })

    // Assert: one of the exec calls must be the mv command
    const calls = execSpy.mock.calls as Array<[string, ...unknown[]]>
    const mvCall = calls.find(([cmd]) => cmd.includes("mv"))
    expect(mvCall).toBeDefined()
    const [mvCmd] = mvCall!
    expect(mvCmd).toContain("/etc/paratix-write.ABCDEF")
    expect(mvCmd).toContain("/etc/large-config")
  })

  it("does not remove a local tmp file after a successful upload", async () => {
    // Arrange
    const client = makeClientWithExecSpy(execSpy)
    const ssh = makeConnectedSsh(client)
    const content = makeLargeContent()

    // Act
    await ssh.writeFile("/etc/large-config", content, { mode: "0600" })

    expect(vi.mocked(writeFileSync)).not.toHaveBeenCalled()
  })

  it("does not create a local tmp file when content upload throws", async () => {
    // Arrange
    vi.mocked(sftpUploadContent).mockRejectedValue(new Error("SFTP transfer failed"))
    const client = makeSimpleClient()
    const ssh = makeConnectedSsh(client)
    const content = makeLargeContent()

    // Act + Assert: the error propagates
    await expect(ssh.writeFile("/etc/large-config", content, { mode: "0600" })).rejects.toThrow(
      "SFTP transfer failed"
    )

    expect(vi.mocked(writeFileSync)).not.toHaveBeenCalled()
  })

  // ---------------------------------------------------------------------------
  // Regression: remote tmp file cleanup after content upload failure
  // ---------------------------------------------------------------------------

  it("calls rm -f for the remote tmp file when content upload throws (best-effort cleanup)", async () => {
    // Arrange
    const remoteTmpPath = "/etc/paratix-write.CLEANUP"
    vi.mocked(sftpUploadContent).mockRejectedValue(new Error("SFTP transfer failed"))
    const remoteCleanupSpy = makeExecSpy(remoteTmpPath, 100_000)
    const client = makeClientWithExecSpy(remoteCleanupSpy)
    const ssh = makeConnectedSsh(client)
    const content = makeLargeContent()

    // Act + Assert: the original content upload error propagates
    await expect(ssh.writeFile("/etc/large-config", content, { mode: "0600" })).rejects.toThrow(
      "SFTP transfer failed"
    )

    // Assert: exec must have been called with rm -f for the remote tmp path.
    // The rm -f is the last exec call (after mktemp and the failed content upload).
    const calls = remoteCleanupSpy.mock.calls as Array<[string, ...unknown[]]>
    const executedCommands = calls.map(([cmd]) => cmd)
    expect(executedCommands).toStrictEqual(
      expect.arrayContaining([expect.stringContaining(`rm -f '${remoteTmpPath}'`)])
    )
  })

  it("swallows an error thrown by the remote rm -f cleanup (best-effort)", async () => {
    // Arrange: content upload succeeds, but rm -f in the finally block throws
    const remoteTmpPath = "/etc/paratix-write.CLEANUP2"

    // exec spy: mktemp returns the remote tmp path, mv succeeds, rm -f fails
    const cleanupExecSpy = vi
      .fn()
      // R-0000141: dirname-symlink probe (realpath) before mktemp
      .mockImplementationOnce(realpathProbeHandler)
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // First call is always mktemp (via output()) — emit the remote tmp path
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from(remoteTmpPath))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // Second call is chmod 0600 — succeeds
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // Third call is mv — succeeds
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // Fourth call is the size verification — succeeds
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from("100000"))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // Fifth call is rm -f — simulates a failure (e.g. permission denied)
        cb(new Error("rm -f failed unexpectedly"), makeStream())
      })

    const client = makeClientWithExecSpy(cleanupExecSpy)
    const ssh = makeConnectedSsh(client)
    const content = makeLargeContent()

    // Act + Assert: writeFile must resolve successfully despite the rm -f failure
    await expect(
      ssh.writeFile("/etc/large-config", content, { mode: "0600" })
    ).resolves.toBeUndefined()
  })

  it("rewrites the target via shell fallback when the atomic SFTP write leaves an empty file", async () => {
    const remoteTmpPath = "/etc/systemd/system/paratix-write.EMPTY"
    const fallbackTmpPath = "/etc/systemd/system/paratix-write.FALLBACK"
    const remotePath = "/etc/systemd/system/example.service"
    const emptyFileExecSpy = vi
      .fn()
      // R-0000141: realpath probe before the initial mktemp.
      .mockImplementationOnce(realpathProbeHandler)
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from(remoteTmpPath))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from("0"))
        stream.emit("close", 0)
      })
      // R-0000141: realpath probe before the privileged shell-fallback mktemp
      .mockImplementationOnce(realpathProbeHandler)
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from(fallbackTmpPath))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from("12"))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })

    const client = makeClientWithExecSpy(emptyFileExecSpy)
    const ssh = makeConnectedSsh(client)
    vi.mocked(sftpUploadContent).mockResolvedValue()

    await expect(
      ssh.writeFile(remotePath, "unit-content", { mode: "0644" })
    ).resolves.toBeUndefined()

    const executedCommands = (emptyFileExecSpy.mock.calls as Array<[string, ...unknown[]]>).map(
      ([command]) => command
    )
    expect(executedCommands.some((command) => command.includes("base64 -d"))).toBe(true)
    expect(executedCommands).toContain(`rm -f '${remoteTmpPath}'`)
    expect(executedCommands).toContain(`rm -f '${fallbackTmpPath}'`)
  })

  it("streams shell-fallback content via stdin instead of argv to avoid ARG_MAX (R-0000093 regression)", async () => {
    // Regression: rewriteRemoteFileViaShell previously embedded the entire
    // base64-encoded payload as a shell argument to `printf '%s'`. For files
    // larger than the kernel ARG_MAX limit (typically 128 KB on Linux) the
    // remote `bash -c '...'` invocation aborted with E2BIG. The fix passes
    // the encoded payload via the stream's stdin and runs `base64 -d`
    // without the argv blob.
    const remoteTmpPath = "/etc/systemd/system/paratix-write.STDIN1"
    const fallbackTmpPath = "/etc/systemd/system/paratix-write.STDIN2"
    const remotePath = "/etc/systemd/system/regression-stdin.service"
    // Use a 200 KB payload — well above the typical printf argv ceiling.
    const largeContent = "x".repeat(200_000)

    const stdinFallbackExecSpy = vi
      .fn()
      // R-0000141: realpath probe before the initial mktemp.
      .mockImplementationOnce(realpathProbeHandler)
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from(remoteTmpPath))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        // Verify the empty-file path so the shell fallback is exercised.
        stream.emit("data", Buffer.from("0"))
        stream.emit("close", 0)
      })
      // R-0000141: realpath probe before the privileged shell-fallback mktemp
      .mockImplementationOnce(realpathProbeHandler)
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from(fallbackTmpPath))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from(String(largeContent.length)))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })

    const client = makeClientWithExecSpy(stdinFallbackExecSpy)
    const ssh = makeConnectedSsh(client)
    vi.mocked(sftpUploadContent).mockResolvedValue()

    await expect(ssh.writeFile(remotePath, largeContent, { mode: "0644" })).resolves.toBeUndefined()

    const executedCommands = (stdinFallbackExecSpy.mock.calls as Array<[string, ...unknown[]]>).map(
      ([command]) => command
    )

    // The shell fallback must use a `base64 -d > <tmp>` redirect — not the
    // legacy `printf '%s' <encoded>` pipeline that placed the payload on argv.
    const fallbackCommand = executedCommands.find((command) =>
      isBase64FallbackCommand(command, fallbackTmpPath)
    )
    expect(fallbackCommand).toBeDefined()
    expect(fallbackCommand).not.toContain("printf '%s'")
    // The command itself must be short — the payload no longer rides on argv.
    expect(fallbackCommand!.length).toBeLessThan(1000)
    // No emitted command should embed the payload.
    expect(executedCommands.some((command) => command.includes(largeContent))).toBe(false)
  })

  // ---------------------------------------------------------------------------
  // Disk-full detection when file is written as 0 bytes
  // ---------------------------------------------------------------------------

  it("throws a disk-full error when the file is empty and df reports no space", async () => {
    const remotePath = "/etc/systemd/system/diskfull.service"
    const dfOutput =
      "Filesystem     1024-blocks    Used Available Capacity Mounted on\n/dev/sda1        10000000 10000000         0     100% /"

    const client = makeClientWithExecSpy(makeDiskCheckExecSpy("DISK", dfOutput))
    const ssh = makeConnectedSsh(client)
    vi.mocked(sftpUploadContent).mockResolvedValue()

    await expect(ssh.writeFile(remotePath, "unit-content", { mode: "0644" })).rejects.toThrow(
      /disk full/v
    )
  })

  it("throws the generic empty-file error when df reports space available", async () => {
    const remotePath = "/etc/systemd/system/notdisk.service"
    const dfOutput =
      "Filesystem     1024-blocks    Used Available Capacity Mounted on\n/dev/sda1        10000000  5000000   5000000      50% /"

    const client = makeClientWithExecSpy(makeDiskCheckExecSpy("NODISK", dfOutput))
    const ssh = makeConnectedSsh(client)
    vi.mocked(sftpUploadContent).mockResolvedValue()

    await expect(ssh.writeFile(remotePath, "unit-content", { mode: "0644" })).rejects.toThrow(
      /remote file is empty/v
    )
  })

  // ---------------------------------------------------------------------------
  // Regression: cleanup error messages must not expose sudo passwords
  // ---------------------------------------------------------------------------

  it("masks sudo password in cleanup error message for writeFile", async () => {
    // Arrange
    const sudoPassword = "mysecretpass"
    const remoteTmpPath = "/etc/paratix-write.MASKSECRET"

    // exec spy: mktemp succeeds, mv succeeds, rm -f fails with an error that
    // contains the sudo password in plain text (simulates a verbose error message)
    const cleanupExecSpy = vi
      .fn()
      // R-0000141: realpath dirname-symlink probe before mktemp
      .mockImplementationOnce(realpathProbeHandler)
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // First call: mktemp — returns the remote tmp path
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from(remoteTmpPath))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // Second call: chmod 0600 — succeeds
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // Third call: mv — succeeds
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // Fourth call: the size verification — succeeds
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from("100000"))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // Fifth call: rm -f — fails with an error whose message contains the password
        cb(
          new Error(`permission denied: echo ${sudoPassword} | sudo rm -f ${remoteTmpPath}`),
          makeStream()
        )
      })

    const client = makeClientWithExecSpy(cleanupExecSpy)
    const ssh = makeConnectedSsh(client)
    ;(ssh as unknown as Record<string, unknown>).cachedSudoPassword = Buffer.from(sudoPassword)
    ;(ssh as unknown as Record<string, unknown>).cachedPasswordString = sudoPassword
    const content = makeLargeContent()

    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true)

    // Act: writeFile must resolve despite the rm -f failure
    await expect(
      ssh.writeFile("/etc/large-config", content, { mode: "0600" })
    ).resolves.toBeUndefined()

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
    const remoteTmpPath = "/etc/paratix-upload.MASKSECRET"
    vi.mocked(stat).mockResolvedValueOnce({ size: 11 } as never)

    // exec spy: mktemp succeeds, mv succeeds, rm -f fails with an error that
    // contains the sudo password in plain text (simulates a verbose error message)
    const cleanupExecSpy = vi
      .fn()
      // R-0000141: realpath dirname-symlink probe before mktemp
      .mockImplementationOnce(realpathProbeHandler)
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // mktemp — returns the remote tmp path
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from(remoteTmpPath))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // chmod 0600 — succeeds
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // R-0000150: stat -c '%s' on staged temp path BEFORE finalize.
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from("11"))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // mv (finalize) — succeeds
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // rm -f — fails with an error whose message contains the password
        cb(
          new Error(`permission denied: echo ${sudoPassword} | sudo rm -f ${remoteTmpPath}`),
          makeStream()
        )
      })

    vi.mocked(sftpUpload).mockResolvedValue()

    const client = makeClientWithExecSpy(cleanupExecSpy)
    const ssh = makeConnectedSsh(client)
    ;(ssh as unknown as Record<string, unknown>).cachedSudoPassword = Buffer.from(sudoPassword)
    ;(ssh as unknown as Record<string, unknown>).cachedPasswordString = sudoPassword

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
