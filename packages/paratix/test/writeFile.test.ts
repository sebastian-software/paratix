import type { Client, SFTPWrapper } from "ssh2"

import { createHash } from "node:crypto"
import { EventEmitter } from "node:events"
import { writeFileSync } from "node:fs"
import { stat } from "node:fs/promises"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { sftpUpload, sftpUploadContent } from "../src/sftp.js"
import { SshConnectionImpl } from "../src/ssh.js"

// R-0000522: SHA-256 over an empty byte sequence — what `sha256sum` prints
// when the remote file was finalized as 0 bytes (e.g. after a disk-full
// truncation). Tests use it to drive the "empty" verdict in
// `verifyRemoteWriteFile` while exercising the shell fallback / disk-full
// branches.
const EMPTY_FILE_SHA256_HEX = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

function sha256Hex(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex")
}

// `sha256sum -- <file>` prints `<64-hex>  <filename>` to stdout. The
// production parser splits on whitespace and takes the first token, so the
// trailing filename is mostly cosmetic — but we keep it so tests mirror
// real-world output and would catch a regression that depended on the
// filename column being present.
function sha256SumOutput(hexHash: string, filename: string): string {
  return `${hexHash}  ${filename}\n`
}

// R-0000599: the post-finalize upload verification streams the local source
// through `createReadStream` + `crypto.createHash` to compute a SHA-256.
// Tests cover the upload pipeline against a mocked filesystem, so the mock
// returns a deterministic 11-byte payload that matches the `stat` mock's
// reported `size: 11`. The constant is declared via `vi.hoisted` so the
// hoisted `vi.mock` factory below can reference it without a TDZ violation.
const { MOCK_LOCAL_UPLOAD_CONTENT, MOCK_LOCAL_UPLOAD_SHA256 } = vi.hoisted(() => ({
  MOCK_LOCAL_UPLOAD_CONTENT: "hello world",
  // SHA-256 of "hello world" — kept inline so tests can match the verify-
  // step `sha256sum` output without re-hashing at runtime.
  MOCK_LOCAL_UPLOAD_SHA256: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
}))

// vi.mock is hoisted to the top of the file by vitest before any imports are
// evaluated, so the module under test receives the mocked version.
vi.mock("node:fs", async () => {
  const { Readable } = await import("node:stream")
  return {
    createReadStream: vi.fn(() => Readable.from([Buffer.from(MOCK_LOCAL_UPLOAD_CONTENT, "utf8")])),
    readFileSync: vi.fn().mockReturnValue(""),
    writeFileSync: vi.fn(),
  }
})

vi.mock("node:fs/promises", () => ({
  stat: vi.fn().mockResolvedValue({ size: 11 }),
}))

vi.mock("../src/sftp.js", () => ({
  SFTP_TIMEOUT: 120_000,
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

type StreamWithStderr = { close: () => void; stderr: EventEmitter } & EventEmitter

type ExecCallback = (err: Error | undefined, stream: StreamWithStderr) => void

function makeStream(): StreamWithStderr {
  const stream = new EventEmitter() as StreamWithStderr
  stream.close = (): void => undefined
  stream.stderr = new EventEmitter()
  return stream
}

// R-0000141: extract the literal directory argument that the dirname-symlink
// probe passed to `realpath -m --`. The probe shape is:
//     realpath -m -- '<dir>'
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

// R-0000522: extract the path argument from `sha256sum -- '<path>'` so the
// mock can echo back the conventional `<hash>  <filename>` output. The
// helper always returns a string (empty when no match) so callers can pass
// it straight into `sha256SumOutput` without inline conditionals — eslint
// flags `?? ""` ternaries in test bodies as "no-conditional-in-test".
const SHA256SUM_PATH_PATTERN = /sha256sum -- '(?<path>[^']*)'/v
function extractSha256SumPath(command: string): string {
  return SHA256SUM_PATH_PATTERN.exec(command)?.groups?.path ?? ""
}

// R-0000522: convenience emitter used by sequence-based mocks — calls the
// exec callback, emits the canonical `<hash>  <filename>` line on stdout,
// and closes the channel with exit 0.
function emitSha256SumResponse(cmd: string, cb: ExecCallback, hexHash: string): void {
  const stream = makeStream()
  cb(undefined, stream)
  stream.emit("data", Buffer.from(sha256SumOutput(hexHash, extractSha256SumPath(cmd))))
  stream.emit("close", 0)
}

function makeDiskCheckExecSpy(prefix: string, dfOutput: string): ReturnType<typeof vi.fn> {
  let counter = 0
  return vi.fn().mockImplementation((cmd: string, cb: ExecCallback) => {
    const stream = makeStream()
    cb(undefined, stream)
    const realpathDirectory = extractRealpathDirectory(cmd)
    const sha256SumPath = extractSha256SumPath(cmd)
    if (realpathDirectory !== "") {
      stream.emit("data", Buffer.from(realpathDirectory))
    } else if (cmd.includes("mktemp")) {
      counter++
      stream.emit("data", Buffer.from(`/etc/systemd/system/paratix-write.${prefix}${counter}`))
    } else if (cmd.includes("stat -c '%s'")) {
      // The disk-check helper still drives the pre-finalize `stat` smoke
      // test through the 0-byte branch — the post-finalize verification
      // below now uses sha256sum instead.
      stream.emit("data", Buffer.from("0"))
    } else if (sha256SumPath !== "") {
      // R-0000522: emit the canonical empty-file SHA-256 so
      // `verifyRemoteWriteFile` reports the "empty" verdict and the
      // disk-full / generic-empty branches in ensureRemoteWriteFile fire
      // exactly as before.
      stream.emit("data", Buffer.from(sha256SumOutput(EMPTY_FILE_SHA256_HEX, sha256SumPath)))
    } else if (cmd.includes("df -P")) {
      stream.emit("data", Buffer.from(dfOutput))
    }
    stream.emit("close", 0)
  })
}

function makeExecSpy(
  mktempResult: string,
  verifiedSize = 100_000,
  // R-0000522: the post-finalize verification now hashes the remote file.
  // Tests that drive the matching path supply the hex hash the production
  // code computed from the same content; defaulting to "" makes the mock
  // emit nothing for `sha256sum`, which mirrors the older "size only"
  // behaviour for tests that never get that far down the pipeline.
  verifiedHash = ""
): ReturnType<typeof vi.fn> {
  return vi.fn().mockImplementation((cmd: string, cb: ExecCallback) => {
    const stream = makeStream()
    cb(undefined, stream)
    const realpathDirectory = extractRealpathDirectory(cmd)
    const sha256SumPath = extractSha256SumPath(cmd)
    if (realpathDirectory !== "") {
      stream.emit("data", Buffer.from(realpathDirectory))
    } else if (cmd.includes("mktemp")) {
      stream.emit("data", Buffer.from(mktempResult))
    } else if (cmd.includes("stat -c '%s'")) {
      stream.emit("data", Buffer.from(String(verifiedSize)))
    } else if (sha256SumPath !== "" && verifiedHash !== "") {
      stream.emit("data", Buffer.from(sha256SumOutput(verifiedHash, sha256SumPath)))
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
    execSpy = makeExecSpy("/etc/paratix-write.SMALL", 11, sha256Hex(makeSmallContent()))
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

    // printf/tee must NOT be used to transport content.
    expect(executedCommands.some((cmd) => isContentTransportPrintf(cmd))).toBe(false)
    expect(executedCommands.some((cmd) => cmd.includes("tee"))).toBe(false)
  })

  it("fails closed when the dirname realpath probe fails", async () => {
    const realpathFailureExecSpy = vi
      .fn()
      .mockImplementationOnce((cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        // R-0000693: assertDirnameHasNoSymlinkComponent now invokes
        // `realpath` through `command -p` so the absolute lookup runs
        // against the POSIX default PATH. The expected literal mirrors that
        // exact shape.
        expect(cmd).toBe("command -p realpath -m -- '/etc'")
        stream.stderr.emit("data", Buffer.from("realpath: command not found"))
        stream.emit("close", 127)
      })
    const client = makeClientWithExecSpy(realpathFailureExecSpy)
    const ssh = makeConnectedSsh(client)

    await expect(
      ssh.writeFile("/etc/config", makeSmallContent(), { mode: "0600" })
    ).rejects.toThrow("realpath -m -- '/etc'")

    expect(vi.mocked(sftpUploadContent)).not.toHaveBeenCalled()
    expect(vi.mocked(writeFileSync)).not.toHaveBeenCalled()
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
    execSpy = makeExecSpy("/etc/paratix-write.ABCDEF", 100_000, sha256Hex(makeLargeContent()))
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
      expect.arrayContaining([expect.stringContaining(`rm -f -- '${remoteTmpPath}'`)])
    )
  })

  it("checks the staged remote tmp size before finalizing the target", async () => {
    const remoteTmpPath = "/etc/paratix-write.STAGING0"
    const remotePath = "/etc/large-config"
    const stagingMismatchExecSpy = vi
      .fn()
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
        stream.emit("data", Buffer.from("0"))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit(
          "data",
          Buffer.from(
            "Filesystem     1024-blocks    Used Available Capacity Mounted on\n/dev/sda1        10000000  5000000   5000000      50% /"
          )
        )
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
    const client = makeClientWithExecSpy(stagingMismatchExecSpy)
    const ssh = makeConnectedSsh(client)
    const content = makeLargeContent()

    await expect(ssh.writeFile(remotePath, content, { mode: "0600" })).rejects.toThrow(
      /remote file size mismatch/v
    )

    const executedCommands = (
      stagingMismatchExecSpy.mock.calls as Array<[string, ...unknown[]]>
    ).map(([cmd]) => cmd)
    expect(executedCommands).toContain(`rm -f -- '${remoteTmpPath}'`)
    expect(executedCommands.join("\n")).not.toContain(`mv -T -- '${remoteTmpPath}' '${remotePath}'`)
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
        // Third call is the staged temp size verification — succeeds
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from("100000"))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // Fourth call is mv — succeeds
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((cmd: string, cb: ExecCallback) => {
        // R-0000522: Fifth call is the post-finalize SHA-256 verification —
        // emit the canonical `<hash>  <filename>` shape with the precomputed
        // expected hash so the verdict is "matches" and writeFile returns
        // before the shell fallback is consulted.
        emitSha256SumResponse(cmd, cb, sha256Hex(makeLargeContent()))
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // Sixth call is rm -f — simulates a failure (e.g. permission denied)
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
    const writtenContent = "unit-content"
    const expectedHash = sha256Hex(writtenContent)
    const emptyFileExecSpy = vi
      .fn()
      .mockImplementationOnce(realpathProbeHandler)
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // [2] mktemp → staged tmp path
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from(remoteTmpPath))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // [3] chmod
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // [4] stat -c '%s' on staged tmp (pre-finalize smoke test) → matches
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from(String(writtenContent.length)))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // [5] mv (finalize)
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((cmd: string, cb: ExecCallback) => {
        // [6] R-0000522: post-finalize SHA-256 verification — emit the
        // canonical empty-file hash so verifyRemoteWriteFile returns
        // "empty" and ensureRemoteWriteFile enters the shell fallback.
        emitSha256SumResponse(cmd, cb, EMPTY_FILE_SHA256_HEX)
      })
      .mockImplementationOnce(realpathProbeHandler)
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // [8] mktemp for privileged shell-fallback temp
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from(fallbackTmpPath))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // [9] base64 -d (content payload via stdin)
        const stream = Object.assign(makeStream(), { end: vi.fn() })
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // [10] chmod on fallback tmp
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // [11] privileged mv finalize for fallback tmp
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // [12] cleanup of fallback tmp (rm -f)
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((cmd: string, cb: ExecCallback) => {
        // [13] R-0000522: post-fallback SHA-256 verification — emit the
        // hash of the originally requested content so the verdict is
        // "matches" and writeFile resolves cleanly.
        emitSha256SumResponse(cmd, cb, expectedHash)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // [14] cleanup of the initial staged tmp (rm -f)
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })

    const client = makeClientWithExecSpy(emptyFileExecSpy)
    const ssh = makeConnectedSsh(client)
    vi.mocked(sftpUploadContent).mockResolvedValue()

    await expect(
      ssh.writeFile(remotePath, writtenContent, { mode: "0644" })
    ).resolves.toBeUndefined()

    const executedCommands = (emptyFileExecSpy.mock.calls as Array<[string, ...unknown[]]>).map(
      ([command]) => command
    )
    expect(executedCommands.some((command) => command.includes("base64 -d"))).toBe(true)
    expect(executedCommands).toContain(`rm -f -- '${remoteTmpPath}'`)
    expect(executedCommands).toContain(`rm -f -- '${fallbackTmpPath}'`)
    // R-0000522: the verify step must hash the remote file instead of running stat on it.
    expect(executedCommands.some((command) => command.includes("sha256sum --"))).toBe(true)
    expect(
      executedCommands.some((command) => command.includes(`stat -c '%s' '${remotePath}'`))
    ).toBe(false)
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
    const fallbackInputStream = Object.assign(makeStream(), { end: vi.fn() })

    const expectedHash = sha256Hex(largeContent)
    const stdinFallbackExecSpy = vi
      .fn()
      // R-0000141: realpath probe before the initial mktemp.
      .mockImplementationOnce(realpathProbeHandler)
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // [2] mktemp → staged tmp path
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from(remoteTmpPath))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // [3] chmod
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // [4] stat -c '%s' on staged tmp (pre-finalize smoke test) → matches
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from(String(largeContent.length)))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // [5] mv (finalize)
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((cmd: string, cb: ExecCallback) => {
        // [6] R-0000522: post-finalize SHA-256 verification — return the
        // empty-file hash so the shell fallback is exercised.
        emitSha256SumResponse(cmd, cb, EMPTY_FILE_SHA256_HEX)
      })
      // R-0000141: realpath probe before the privileged shell-fallback mktemp
      .mockImplementationOnce(realpathProbeHandler)
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // [8] mktemp for privileged shell-fallback temp
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from(fallbackTmpPath))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // [9] base64 -d (content payload via stdin)
        cb(undefined, fallbackInputStream)
        fallbackInputStream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // [10] chmod on fallback tmp
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // [11] privileged mv finalize for fallback tmp
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // [12] cleanup of fallback tmp (rm -f)
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((cmd: string, cb: ExecCallback) => {
        // [13] R-0000522: post-fallback SHA-256 verification — emit the
        // hash of the originally requested content so the verdict is
        // "matches" and writeFile resolves cleanly.
        emitSha256SumResponse(cmd, cb, expectedHash)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // [14] cleanup of the initial staged tmp (rm -f)
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
    expect(fallbackInputStream.end).toHaveBeenCalledExactlyOnceWith(
      Buffer.from(largeContent, "utf8").toString("base64")
    )
    const [fallbackInput] = fallbackInputStream.end.mock.calls[0] as [string]
    expect(Buffer.from(fallbackInput, "base64").toString("utf8")).toBe(largeContent)
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
      /remote file size mismatch/v
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
        // Third call: staged temp size verification — succeeds
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from("100000"))
        stream.emit("close", 0)
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // Fourth call: mv — succeeds
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("close", 0)
      })
      .mockImplementationOnce((cmd: string, cb: ExecCallback) => {
        // R-0000522: Fifth call — post-finalize SHA-256 verification.
        // Emit the precomputed hash of the original content so the
        // verdict is "matches" and writeFile resolves before the shell
        // fallback is consulted.
        emitSha256SumResponse(cmd, cb, sha256Hex(makeLargeContent()))
      })
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        // Sixth call: rm -f — fails with an error whose message contains the password
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
      .mockImplementationOnce((cmd: string, cb: ExecCallback) => {
        // R-0000599: post-finalize SHA-256 verification — echo the canonical
        // `<hash>  <filename>` line so verifyRemoteWriteFile returns "matches".
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit(
          "data",
          Buffer.from(sha256SumOutput(MOCK_LOCAL_UPLOAD_SHA256, extractSha256SumPath(cmd)))
        )
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
