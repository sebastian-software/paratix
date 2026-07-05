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
// `classifyRemoteHash` while exercising the shell fallback / disk-full
// branches.
const EMPTY_FILE_SHA256_HEX = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

function sha256Hex(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex")
}

// R-0000599: the post-finalize upload verification streams the local source
// through `createReadStream` + `crypto.createHash` to compute a SHA-256.
// Tests cover the upload pipeline against a mocked filesystem, so the mock
// returns a deterministic 11-byte payload that matches the `stat` mock's
// reported `size: 11`. The constant is declared via `vi.hoisted` so the
// hoisted `vi.mock` factory below can reference it without a TDZ violation.
const { MOCK_LOCAL_UPLOAD_CONTENT } = vi.hoisted(() => ({
  MOCK_LOCAL_UPLOAD_CONTENT: "hello world",
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

// The legacy content-transport pipeline embedded the payload as
// `printf '%s' '<encoded>'`. The batched write scripts (#82) use `printf`
// only for short diagnostic markers (`paratix-hash-failed`,
// `paratix-symlink-component`, the finalize guard message), never to carry
// content — so the precise `printf '%s' '` shape distinguishes them.
function isContentTransportPrintf(command: string): boolean {
  return command.includes("printf '%s' '")
}

type StreamWithStderr = {
  close: () => void
  end: (input?: unknown) => void
  stderr: EventEmitter
} & EventEmitter

type ExecCallback = (err: Error | undefined, stream: StreamWithStderr) => void

function makeStream(): StreamWithStderr {
  const stream = new EventEmitter() as StreamWithStderr
  stream.close = (): void => undefined
  stream.end = (): void => undefined
  stream.stderr = new EventEmitter()
  return stream
}

// R-0000141: extract the literal directory argument that the dirname-symlink
// probe passed to `realpath -m --`. Only the shell-fallback path
// (`createRemotePrivilegedTempPathInDestination`) still issues a standalone
// `realpath` probe; the batched prep/finalize scripts fold it in.
const REALPATH_DIRECTORY_PATTERN = /realpath -m -- '(?<directory>[^']*)'/v
function extractRealpathDirectory(command: string): string {
  return REALPATH_DIRECTORY_PATTERN.exec(command)?.groups?.directory ?? ""
}

// #82: with the batched write path a single remote command now bundles
// several operations, so the mock classifies each command by content rather
// than by call index:
//
//   - `sha256sum` + `mv -T`  → combined finalize+verify → emit `finalizeHash`.
//   - `sha256sum` (no `mv`)  → shell-fallback re-verify  → emit `verifyHash`.
//   - `stat -c '%s'`         → combined chmod+size stage → emit `size`.
//   - `df -Pk`               → disk-space probe          → emit `dfOutput`.
//   - `mktemp` + `realpath`  → combined prep script (root) → emit `tempPath`.
//   - `mktemp` (no realpath) → privileged shell-fallback mktemp → emit `fallbackTempPath`.
//   - `realpath` (no mktemp) → shell-fallback dirname probe → echo the directory.
type WriteExecOptions = {
  dfOutput?: string
  fallbackTempPath?: string
  finalizeHash?: string
  inputStream?: StreamWithStderr
  size?: number
  tempPath: string
  verifyHash?: string
}

function writeMktempResponse(command: string, options: WriteExecOptions): string {
  if (command.includes("realpath")) return options.tempPath
  return options.fallbackTempPath ?? options.tempPath
}

function writeHashResponse(command: string, options: WriteExecOptions): string {
  const hash = command.includes("mv -T") ? (options.finalizeHash ?? "") : (options.verifyHash ?? "")
  return `${hash}  x\n`
}

function writeResponseData(command: string, options: WriteExecOptions): string {
  if (command.includes("sha256sum")) return writeHashResponse(command, options)
  if (command.includes("stat -c '%s'")) return String(options.size ?? 0)
  if (command.includes("df -Pk")) return options.dfOutput ?? ""
  if (command.includes("mktemp")) return writeMktempResponse(command, options)
  // Standalone dirname-symlink probe on the (root) shell-fallback path — echo
  // the directory back unchanged so the equality check passes.
  if (command.includes("realpath")) return extractRealpathDirectory(command)
  return ""
}

function makeWriteExec(options: WriteExecOptions): ReturnType<typeof vi.fn> {
  return vi.fn().mockImplementation((command: string, callback: ExecCallback) => {
    const isBase64Input = command.includes("base64 -d") && options.inputStream != null
    const stream = isBase64Input ? options.inputStream! : makeStream()
    callback(undefined, stream)
    const data = writeResponseData(command, options)
    stream.emit("data", Buffer.from(data))
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

function commandsOf(execSpy: ReturnType<typeof vi.fn>): string[] {
  return (execSpy.mock.calls as Array<[string, ...unknown[]]>).map(([command]) => command)
}

// ---------------------------------------------------------------------------
// Tests — small content (atomic write via SFTP, same as large content)
// ---------------------------------------------------------------------------

describe("SshConnectionImpl.writeFile — small content", () => {
  let execSpy: ReturnType<typeof vi.fn>

  beforeEach(() => {
    const hash = sha256Hex(makeSmallContent())
    execSpy = makeWriteExec({
      finalizeHash: hash,
      size: 11,
      tempPath: "/etc/paratix-write.SMALL",
      verifyHash: hash,
    })
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

    // exec calls: prep (mktemp), stage (chmod+stat), finalize (mv+sha256sum)
    const executedCommands = commandsOf(execSpy)
    expect(executedCommands.some((cmd) => cmd.includes("mktemp"))).toBe(true)
    expect(executedCommands.some((cmd) => cmd.includes("mv -T"))).toBe(true)

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
        // #82: the R-0000141/R-0000693 dirname-symlink guard is now folded
        // into the combined `set -eu` prep script that also runs `mktemp`.
        // A realpath failure aborts the whole prep round-trip.
        expect(cmd).toContain("command -p realpath -m -- '/etc'")
        expect(cmd).toContain("mktemp -p '/etc'")
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
    const hash = sha256Hex(makeLargeContent())
    execSpy = makeWriteExec({
      finalizeHash: hash,
      size: 100_000,
      tempPath: "/etc/paratix-write.ABCDEF",
      verifyHash: hash,
    })
    vi.mocked(sftpUploadContent).mockResolvedValue()
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  it("does not create a local content file via writeFileSync", async () => {
    const client = makeClientWithExecSpy(execSpy)
    const ssh = makeConnectedSsh(client)

    await ssh.writeFile("/etc/large-config", makeLargeContent(), { mode: "0600" })

    expect(vi.mocked(writeFileSync)).not.toHaveBeenCalled()
  })

  it("calls sftpUploadContent with the content and the remote tmp path", async () => {
    const client = makeClientWithExecSpy(execSpy)
    const ssh = makeConnectedSsh(client)
    const content = makeLargeContent()

    await ssh.writeFile("/etc/large-config", content, { mode: "0600" })

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
    const client = makeClientWithExecSpy(execSpy)
    const ssh = makeConnectedSsh(client)

    await ssh.writeFile("/etc/large-config", makeLargeContent(), { mode: "0600" })

    // The finalize round-trip bundles the guard, `mv -T` and `sha256sum`.
    const mvCall = commandsOf(execSpy).find((cmd) => cmd.includes("mv -T"))
    expect(mvCall).toBeDefined()
    expect(mvCall).toContain("/etc/paratix-write.ABCDEF")
    expect(mvCall).toContain("/etc/large-config")
    expect(mvCall).toContain("sha256sum --")
  })

  it("does not remove a local tmp file after a successful upload", async () => {
    const client = makeClientWithExecSpy(execSpy)
    const ssh = makeConnectedSsh(client)

    await ssh.writeFile("/etc/large-config", makeLargeContent(), { mode: "0600" })

    expect(vi.mocked(writeFileSync)).not.toHaveBeenCalled()
  })

  it("skips the remote rm -f round-trip after a successful finalize (#82)", async () => {
    // #82: a successful finalize consumes the staged temp via `mv`, so the
    // best-effort `rm -f` cleanup — and its extra exec round-trip — is skipped
    // on the success path. Only prep, stage and finalize should reach the wire.
    const client = makeClientWithExecSpy(execSpy)
    const ssh = makeConnectedSsh(client)

    await ssh.writeFile("/etc/large-config", makeLargeContent(), { mode: "0600" })

    const executedCommands = commandsOf(execSpy)
    expect(executedCommands.some((cmd) => cmd.includes("rm -f"))).toBe(false)
    // Exactly three exec round-trips besides the SFTP transfer.
    expect(executedCommands).toHaveLength(3)
  })

  it("does not create a local tmp file when content upload throws", async () => {
    vi.mocked(sftpUploadContent).mockRejectedValue(new Error("SFTP transfer failed"))
    const client = makeClientWithExecSpy(execSpy)
    const ssh = makeConnectedSsh(client)

    await expect(
      ssh.writeFile("/etc/large-config", makeLargeContent(), { mode: "0600" })
    ).rejects.toThrow("SFTP transfer failed")

    expect(vi.mocked(writeFileSync)).not.toHaveBeenCalled()
  })

  // ---------------------------------------------------------------------------
  // Regression: remote tmp file cleanup after content upload failure
  // ---------------------------------------------------------------------------

  it("calls rm -f for the remote tmp file when content upload throws (best-effort cleanup)", async () => {
    const remoteTmpPath = "/etc/paratix-write.CLEANUP"
    vi.mocked(sftpUploadContent).mockRejectedValue(new Error("SFTP transfer failed"))
    const remoteCleanupSpy = makeWriteExec({ size: 100_000, tempPath: remoteTmpPath })
    const client = makeClientWithExecSpy(remoteCleanupSpy)
    const ssh = makeConnectedSsh(client)

    await expect(
      ssh.writeFile("/etc/large-config", makeLargeContent(), { mode: "0600" })
    ).rejects.toThrow("SFTP transfer failed")

    // The staged temp survives an SFTP failure, so the finally block removes it.
    expect(commandsOf(remoteCleanupSpy)).toStrictEqual(
      expect.arrayContaining([expect.stringContaining(`rm -f -- '${remoteTmpPath}'`)])
    )
  })

  it("checks the staged remote tmp size before finalizing the target", async () => {
    const remoteTmpPath = "/etc/paratix-write.STAGING0"
    const remotePath = "/etc/large-config"
    const stagingMismatchExecSpy = makeWriteExec({
      dfOutput:
        "Filesystem     1024-blocks    Used Available Capacity Mounted on\n/dev/sda1        10000000  5000000   5000000      50% /",
      size: 0,
      tempPath: remoteTmpPath,
    })
    const client = makeClientWithExecSpy(stagingMismatchExecSpy)
    const ssh = makeConnectedSsh(client)

    await expect(ssh.writeFile(remotePath, makeLargeContent(), { mode: "0600" })).rejects.toThrow(
      /remote file size mismatch/v
    )

    const executedCommands = commandsOf(stagingMismatchExecSpy)
    // The staged size check runs BEFORE the finalize, so `mv` never happens
    // and the finally block removes the staged temp.
    expect(executedCommands).toContain(`rm -f -- '${remoteTmpPath}'`)
    expect(executedCommands.some((cmd) => cmd.includes("mv -T"))).toBe(false)
  })

  it("swallows an error thrown by the remote rm -f cleanup on a failure path (best-effort)", async () => {
    // #82: cleanup now runs only when a failure leaves the staged temp behind.
    // A cleanup `rm -f` failure must not mask the original error.
    const remoteTmpPath = "/etc/paratix-write.CLEANUP2"
    vi.mocked(sftpUploadContent).mockRejectedValue(new Error("SFTP transfer failed"))

    const cleanupExecSpy = vi
      .fn()
      // prep — returns the staged temp path
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from(remoteTmpPath))
        stream.emit("close", 0)
      })
      // rm -f in finally — simulates a failure (e.g. permission denied)
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        cb(new Error("rm -f failed unexpectedly"), makeStream())
      })

    const client = makeClientWithExecSpy(cleanupExecSpy)
    const ssh = makeConnectedSsh(client)

    await expect(
      ssh.writeFile("/etc/large-config", makeLargeContent(), { mode: "0600" })
    ).rejects.toThrow("SFTP transfer failed")
  })

  it("rewrites the target via shell fallback when the atomic SFTP write leaves an empty file", async () => {
    const remoteTmpPath = "/etc/systemd/system/paratix-write.EMPTY"
    const fallbackTmpPath = "/etc/systemd/system/paratix-write.FALLBACK"
    const remotePath = "/etc/systemd/system/example.service"
    const writtenContent = "unit-content"
    const execSpy2 = makeWriteExec({
      fallbackTempPath: fallbackTmpPath,
      // finalize verdict is "empty" → shell fallback runs
      finalizeHash: EMPTY_FILE_SHA256_HEX,
      size: writtenContent.length,
      tempPath: remoteTmpPath,
      // post-fallback re-verification settles on "matches"
      verifyHash: sha256Hex(writtenContent),
    })

    const client = makeClientWithExecSpy(execSpy2)
    const ssh = makeConnectedSsh(client)
    vi.mocked(sftpUploadContent).mockResolvedValue()

    await expect(
      ssh.writeFile(remotePath, writtenContent, { mode: "0644" })
    ).resolves.toBeUndefined()

    const executedCommands = commandsOf(execSpy2)
    expect(executedCommands.some((cmd) => cmd.includes("base64 -d"))).toBe(true)
    // The shell-fallback temp is cleaned up; the initial staged temp is not
    // rm'd because the (empty) finalize already consumed it via `mv`.
    expect(executedCommands).toContain(`rm -f -- '${fallbackTmpPath}'`)
    expect(executedCommands).not.toContain(`rm -f -- '${remoteTmpPath}'`)
    // R-0000522: verification hashes the remote file rather than stat-ing it.
    expect(executedCommands.some((cmd) => cmd.includes("sha256sum --"))).toBe(true)
    expect(executedCommands.some((cmd) => cmd.includes(`stat -c '%s' '${remotePath}'`))).toBe(false)
  })

  it("streams shell-fallback content via stdin instead of argv to avoid ARG_MAX (R-0000093 regression)", async () => {
    // Regression: rewriteRemoteFileViaShell previously embedded the entire
    // base64-encoded payload as a shell argument to `printf '%s'`. For files
    // larger than the kernel ARG_MAX limit the remote `bash -c '...'`
    // invocation aborted with E2BIG. The fix passes the encoded payload via
    // the stream's stdin and runs `base64 -d` without the argv blob.
    const remoteTmpPath = "/etc/systemd/system/paratix-write.STDIN1"
    const fallbackTmpPath = "/etc/systemd/system/paratix-write.STDIN2"
    const remotePath = "/etc/systemd/system/regression-stdin.service"
    const largeContent = "x".repeat(200_000)
    const fallbackInputStream = Object.assign(makeStream(), { end: vi.fn() })

    // The base64 payload is streamed via stdin — hand back a stream whose `end`
    // is a spy so the test can assert the encoded content.
    const stdinFallbackExecSpy = makeWriteExec({
      fallbackTempPath: fallbackTmpPath,
      finalizeHash: EMPTY_FILE_SHA256_HEX,
      inputStream: fallbackInputStream,
      size: largeContent.length,
      tempPath: remoteTmpPath,
      verifyHash: sha256Hex(largeContent),
    })

    const client = makeClientWithExecSpy(stdinFallbackExecSpy)
    const ssh = makeConnectedSsh(client)
    vi.mocked(sftpUploadContent).mockResolvedValue()

    await expect(ssh.writeFile(remotePath, largeContent, { mode: "0644" })).resolves.toBeUndefined()

    const executedCommands = (stdinFallbackExecSpy.mock.calls as Array<[string, ...unknown[]]>).map(
      ([command]) => command
    )
    const fallbackCommand = executedCommands.find((command) =>
      isBase64FallbackCommand(command, fallbackTmpPath)
    )
    expect(fallbackCommand).toBeDefined()
    expect(fallbackCommand).not.toContain("printf '%s'")
    expect(fallbackCommand!.length).toBeLessThan(1000)
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
    const execSpy2 = makeWriteExec({
      dfOutput:
        "Filesystem     1024-blocks    Used Available Capacity Mounted on\n/dev/sda1        10000000 10000000         0     100% /",
      // staged size reads back as 0 → disk-space probe fires
      size: 0,
      tempPath: "/etc/systemd/system/paratix-write.DISK",
    })
    const client = makeClientWithExecSpy(execSpy2)
    const ssh = makeConnectedSsh(client)
    vi.mocked(sftpUploadContent).mockResolvedValue()

    await expect(ssh.writeFile(remotePath, "unit-content", { mode: "0644" })).rejects.toThrow(
      /disk full/v
    )
  })

  it("throws the generic empty-file error when df reports space available", async () => {
    const remotePath = "/etc/systemd/system/notdisk.service"
    const execSpy2 = makeWriteExec({
      dfOutput:
        "Filesystem     1024-blocks    Used Available Capacity Mounted on\n/dev/sda1        10000000  5000000   5000000      50% /",
      size: 0,
      tempPath: "/etc/systemd/system/paratix-write.NODISK",
    })
    const client = makeClientWithExecSpy(execSpy2)
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
    // #82: cleanup runs only on failure paths now. Drive a staged size
    // mismatch so the finally block removes the staged temp; the `rm -f`
    // failure carries a plain-text password that must be masked in the warning.
    const sudoPassword = "mysecretpass"
    const remoteTmpPath = "/etc/paratix-write.MASKSECRET"

    const cleanupExecSpy = vi
      .fn()
      // prep — returns the staged temp path
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from(remoteTmpPath))
        stream.emit("close", 0)
      })
      // stage chmod+stat — reports 0 bytes to force a size mismatch
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from("0"))
        stream.emit("close", 0)
      })
      // df -Pk — reports plenty of space, so the verdict is a size mismatch
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
      // rm -f in finally — fails with an error whose message contains the password
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
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

    await expect(ssh.writeFile("/etc/large-config", content, { mode: "0600" })).rejects.toThrow(
      /remote file size mismatch/v
    )

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
    // #82: drive a staged size mismatch (mocked local size 42 vs staged 0) so
    // the finally block removes the staged temp; the `rm -f` failure carries a
    // plain-text password that must be masked in the warning.
    const sudoPassword = "upload-secret-pw"
    const remoteTmpPath = "/etc/paratix-upload.MASKSECRET"
    vi.mocked(stat).mockResolvedValueOnce({ size: 42 } as never)

    const cleanupExecSpy = vi
      .fn()
      // prep — returns the staged temp path
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from(remoteTmpPath))
        stream.emit("close", 0)
      })
      // stage chmod+stat — reports 0 bytes to force a size mismatch
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
        const stream = makeStream()
        cb(undefined, stream)
        stream.emit("data", Buffer.from("0"))
        stream.emit("close", 0)
      })
      // df -Pk — reports plenty of space, so the verdict is a size mismatch
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
      // rm -f in finally — fails with an error whose message contains the password
      .mockImplementationOnce((_cmd: string, cb: ExecCallback) => {
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

    await expect(ssh.uploadFile("/local/path/file.txt", "/etc/file.txt")).rejects.toThrow(
      /remote file size mismatch/v
    )

    const stderrOutput = stderrSpy.mock.calls.map((args) => String(args[0])).join("")
    expect(stderrOutput).not.toContain(sudoPassword)
    expect(stderrOutput).toContain("[REDACTED]")

    stderrSpy.mockRestore()
  })
})
