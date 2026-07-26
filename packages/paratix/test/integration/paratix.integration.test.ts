import { execFile } from "node:child_process"
import { createHash, randomUUID } from "node:crypto"
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs"
import { readFile, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { pathToFileURL } from "node:url"
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest"

import type { Environment, Module, SshConfig, SshConnection } from "../../src/types.js"

import { command, download, file, shellQuote } from "../../src/index.js"
import { clearHostKeyCache, HostKeyVerificationError } from "../../src/knownHosts.js"
import { runPlaybook } from "../../src/runner.js"
import { server } from "../../src/server.js"
import { SshConnectionImpl } from "../../src/ssh.js"
import {
  createIntegrationEnvironment,
  type IntegrationEnvironment,
  restoreHomeEnvironmentVariable,
} from "./harness.js"

const emptyEnv = {}
const HTTP_SERVER_READY_DELAY_MS = 250
const HTTP_SERVER_READY_RETRIES = 20
const CLI_COMMAND_TIMEOUT_MS = 60_000
const CLI_COMMAND_FAILURE_OUTPUT_LIMIT = 8 * 1024
const CLI_COMMAND_MAX_BUFFER = 10 * 1024 * 1024
const unicodeFileName = "über datei こんにちは.txt"
const unicodeTemplateName = "grüße-vorlage.tmpl"
const unicodeContent = "Grüße aus Köln – こんにちは мир\n"
const unicodeBlockContent = "Block Grüße\nこんにちは\nПривет"

let integrationEnvironment: IntegrationEnvironment | undefined
let originalHome: string | undefined
let testHome: string
let nextHttpPort = 18_080

type RemoteStat = {
  group: string
  mode: string
  owner: string
}

type CleanupStep = {
  name: string
  run: () => Promise<void> | void
}

class CliCommandExecutionError extends Error {
  public readonly stderr: string
  public readonly stdout: string

  public constructor(
    message: string,
    streams: { stderr: string; stdout: string },
    options: { cause: Error }
  ) {
    super(message, options)
    this.name = "CliCommandExecutionError"
    this.stderr = streams.stderr
    this.stdout = streams.stdout
  }
}

function getEnvironment(): IntegrationEnvironment {
  if (integrationEnvironment == null) {
    throw new Error("Integration environment has not been initialized")
  }
  return integrationEnvironment
}

function createSshConfig(
  ports: number[],
  overrides: Partial<SshConfig> = {},
  user = "paratix"
): SshConfig {
  const environment = getEnvironment()
  return {
    expectedHostPublicKey: environment.hostPublicKey,
    ports,
    privateKey: environment.clientPrivateKeyPath,
    strictHostKeyChecking: "yes",
    user,
    ...overrides,
  }
}

async function connectSsh(
  ports: number[],
  overrides: Partial<SshConfig> = {},
  user = "paratix"
): Promise<SshConnectionImpl> {
  const environment = getEnvironment()
  const ssh = new SshConnectionImpl(environment.host, createSshConfig(ports, overrides, user))
  await ssh.connect()
  return ssh
}

function allocateHttpPort(): number {
  const port = nextHttpPort
  nextHttpPort += 1
  return port
}

function buildLargeDownloadFlagName(parameters: {
  destination: string
  headers?: Record<string, string>
  url: string
}): string {
  const flagKey = JSON.stringify({
    destination: parameters.destination,
    headers: JSON.stringify(
      Object.entries(parameters.headers ?? {}).sort(([leftName], [rightName]) =>
        leftName.localeCompare(rightName)
      )
    ),
    url: parameters.url,
  })
  return `download-${createHash("sha256").update(flagKey).digest("hex")}`
}

async function readRemoteStat(ssh: SshConnection, remotePath: string): Promise<RemoteStat> {
  const raw = await ssh.output(`stat -c '%a %U %G' ${shellQuote(remotePath)}`)
  const [mode = "", owner = "", group = ""] = raw.trim().split(" ")
  return { group, mode, owner }
}

function createAcceptNewSshConfig(port: number): SshConfig {
  const environment = getEnvironment()
  return {
    ports: [port],
    privateKey: environment.clientPrivateKeyPath,
    strictHostKeyChecking: "accept-new",
    user: "paratix",
  }
}

function createKnownHostsSshConfig(port: number): SshConfig {
  const environment = getEnvironment()
  return {
    ports: [port],
    privateKey: environment.clientPrivateKeyPath,
    strictHostKeyChecking: "yes",
    user: "paratix",
  }
}

async function connectWithConfig(config: SshConfig): Promise<SshConnectionImpl> {
  const ssh = new SshConnectionImpl(getEnvironment().host, config)
  await ssh.connect()
  return ssh
}

function createTamperedHostPublicKey(publicKey: string): string {
  const [algorithm = "", base64Key = ""] = publicKey.trim().split(/\s+/v)
  const key = Buffer.from(base64Key, "base64")
  key[key.length - 1] ^= 1
  return `${algorithm} ${key.toString("base64")}`
}

async function sleep(delayMs: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, delayMs)
  })
}

async function execFileText(
  executablePath: string,
  commandArguments: string[],
  options: {
    cwd: string
    env?: NodeJS.ProcessEnv
  }
): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      executablePath,
      commandArguments,
      {
        cwd: options.cwd,
        encoding: "utf8",
        env: options.env,
        killSignal: "SIGTERM",
        maxBuffer: CLI_COMMAND_MAX_BUFFER,
        timeout: CLI_COMMAND_TIMEOUT_MS,
      },
      (error, stdout, stderr) => {
        if (error != null) {
          const cause =
            error instanceof Error ? error : new Error("Command execution failed", { cause: error })
          reject(
            new CliCommandExecutionError(
              formatCliCommandFailureMessage(executablePath, commandArguments, {
                stderr,
                stdout,
              }),
              { stderr, stdout },
              { cause }
            )
          )
          return
        }
        resolve(stdout)
      }
    )
  })
}

function tailCliCommandOutput(output: string): string {
  if (output.length <= CLI_COMMAND_FAILURE_OUTPUT_LIMIT) return output
  return output.slice(-CLI_COMMAND_FAILURE_OUTPUT_LIMIT)
}

function formatCliCommandFailureStream(label: "stderr" | "stdout", output: string): string {
  const tail = tailCliCommandOutput(output).trim()
  if (tail.length === 0) return ""
  return `${label}:\n${tail}`
}

function formatCliCommandFailureMessage(
  executablePath: string,
  commandArguments: string[],
  streams: { stderr: string; stdout: string }
): string {
  const details = [
    formatCliCommandFailureStream("stdout", streams.stdout),
    formatCliCommandFailureStream("stderr", streams.stderr),
  ]
    .filter((detail) => detail.length > 0)
    .join("\n")
  const suffix = details.length > 0 ? `\n${details}` : ""
  return `Command failed: ${executablePath} ${commandArguments.join(" ")}${suffix}`
}

async function expectModuleCheckOk(
  mod: Module,
  ssh: SshConnection,
  environment: Environment = emptyEnv
): Promise<void> {
  await expect(mod.check(ssh, environment)).resolves.toBe("ok")
}

async function runCleanupSteps(steps: CleanupStep[], primaryError?: unknown): Promise<void> {
  const failures: Error[] = []

  await runCleanupStep(steps, 0, failures)

  if (failures.length === 0) return

  const cleanupError = new AggregateError(failures, "One or more cleanup steps failed")
  if (primaryError != null) {
    attachCleanupFailureDiagnostic(primaryError, cleanupError)
    return
  }

  throw cleanupError
}

function attachCleanupFailureDiagnostic(primaryError: unknown, cleanupError: AggregateError): void {
  if (!(primaryError instanceof Error)) return

  const errorWithDiagnostic = primaryError
  Object.defineProperty(errorWithDiagnostic, "cleanupError", {
    configurable: true,
    value: cleanupError,
  })
  errorWithDiagnostic.stack = [
    errorWithDiagnostic.stack ?? errorWithDiagnostic.message,
    "",
    "Cleanup failure after primary error:",
    ...cleanupError.errors.map((error) => (error instanceof Error ? error.message : String(error))),
    cleanupError.stack ?? cleanupError.message,
  ].join("\n")
}

async function runCleanupStep(
  steps: CleanupStep[],
  index: number,
  failures: Error[]
): Promise<void> {
  const step = steps.at(index)
  if (step == null) return

  try {
    await step.run()
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    failures.push(new Error(`${step.name}: ${reason}`))
  }

  await runCleanupStep(steps, index + 1, failures)
}

function removeRemoteDirectoryStep(
  ssh: SshConnection,
  remoteDirectory: string,
  name = "remove remote test directory"
): CleanupStep {
  return {
    name,
    async run() {
      await ssh.exec(`rm -rf ${shellQuote(remoteDirectory)}`, { silent: true })
    },
  }
}

function disconnectSshStep(ssh: SshConnection): CleanupStep {
  return {
    name: "disconnect SSH",
    run() {
      ssh.disconnect()
    },
  }
}

function removeLocalDirectoryStep(localDirectory: string): CleanupStep {
  return {
    name: "remove local test directory",
    async run() {
      await rm(localDirectory, { force: true, recursive: true })
    },
  }
}

function removeCreatedLocalDirectoryStep(getLocalDirectory: () => string | undefined): CleanupStep {
  return {
    name: "remove local test directory",
    async run() {
      const localDirectory = getLocalDirectory()
      if (localDirectory == null) return

      await removeLocalDirectoryStep(localDirectory).run()
    },
  }
}

async function startRemoteHttpServer(
  ssh: SshConnection,
  directory: string,
  port: number
): Promise<void> {
  const pidPath = `/tmp/paratix-http-${String(port)}.pid`
  const logPath = `/tmp/paratix-http-${String(port)}.log`
  await ssh.exec(
    `sh -lc ${shellQuote(
      `cd ${shellQuote(directory)} && nohup python3 -m http.server ${String(port)} --bind 127.0.0.1 >${shellQuote(logPath)} 2>&1 & echo $! > ${shellQuote(pidPath)}`
    )}`,
    { silent: true }
  )
}

async function stopRemoteHttpServer(ssh: SshConnection, port: number): Promise<void> {
  const pidPath = `/tmp/paratix-http-${String(port)}.pid`
  const logPath = `/tmp/paratix-http-${String(port)}.log`
  await ssh.exec(
    `sh -lc ${shellQuote(
      `if [ -f ${shellQuote(pidPath)} ]; then kill "$(cat ${shellQuote(pidPath)})" || true; fi; rm -f ${shellQuote(pidPath)} ${shellQuote(logPath)}`
    )}`,
    { silent: true }
  )
}

async function waitForRemoteHttpServer(
  ssh: SshConnection,
  url: string,
  retries = HTTP_SERVER_READY_RETRIES
): Promise<void> {
  if (await ssh.test(`curl -fsS ${shellQuote(url)} >/dev/null`)) return
  if (retries <= 1) {
    throw new Error(`Timed out waiting for remote HTTP server at ${url}`)
  }

  await sleep(HTTP_SERVER_READY_DELAY_MS)
  await waitForRemoteHttpServer(ssh, url, retries - 1)
}

describe("cleanup helper", () => {
  it("runs every cleanup step even when an earlier cleanup fails", async () => {
    const calls: string[] = []

    await expect(
      runCleanupSteps([
        {
          name: "remote cleanup",
          run() {
            calls.push("remote")
            throw new Error("remote cleanup failed")
          },
        },
        {
          name: "disconnect",
          run() {
            calls.push("disconnect")
          },
        },
        {
          name: "local cleanup",
          run() {
            calls.push("local")
          },
        },
      ])
    ).rejects.toThrow(AggregateError)

    expect(calls).toStrictEqual(["remote", "disconnect", "local"])
  })

  it("keeps the primary error when cleanup also fails", async () => {
    const primaryError = new Error("primary failure")

    await expect(async () => {
      try {
        throw primaryError
      } catch (error) {
        await runCleanupSteps(
          [
            {
              name: "remote cleanup",
              run() {
                throw new Error("cleanup failed")
              },
            },
          ],
          error
        )
        throw error
      }
    }).rejects.toBe(primaryError)

    expect(primaryError.stack).toContain("Cleanup failure after primary error")
    expect(primaryError.stack).toContain("remote cleanup: cleanup failed")
    expect((primaryError as { cleanupError?: AggregateError } & Error).cleanupError).toBeInstanceOf(
      AggregateError
    )
  })

  it("throws cleanup errors directly when no primary error exists", async () => {
    await expect(
      runCleanupSteps([
        {
          name: "remote cleanup",
          run() {
            throw new Error("cleanup failed")
          },
        },
      ])
    ).rejects.toThrow(AggregateError)
  })
})

describe("CLI command helper", () => {
  it("includes stdout and stderr tails when the CLI process fails", async () => {
    const localDirectory = mkdtempSync(join(tmpdir(), "paratix-cli-helper-"))
    const scriptPath = join(localDirectory, "fail.mjs")

    try {
      writeFileSync(
        scriptPath,
        [
          "process.stdout.write('stdout diagnostic\\n')",
          "process.stderr.write('stderr diagnostic\\n')",
          "process.exit(1)",
          "",
        ].join("\n")
      )

      await expect(
        execFileText(process.execPath, [scriptPath], {
          cwd: localDirectory,
        })
      ).rejects.toThrow("stdout:\nstdout diagnostic\nstderr:\nstderr diagnostic")
    } finally {
      await rm(localDirectory, { force: true, recursive: true })
    }
  })

  it("bounds CLI failure stdout and stderr details", async () => {
    const localDirectory = mkdtempSync(join(tmpdir(), "paratix-cli-helper-"))
    const scriptPath = join(localDirectory, "fail-large.mjs")
    const longStdout = `stdout-start\n${"o".repeat(9000)}stdout-end`
    const longStderr = `stderr-start\n${"e".repeat(9000)}stderr-end`

    try {
      writeFileSync(
        scriptPath,
        [
          `process.stdout.write(${JSON.stringify(longStdout)})`,
          `process.stderr.write(${JSON.stringify(longStderr)})`,
          "process.exit(1)",
          "",
        ].join("\n")
      )

      let caughtError: unknown
      try {
        await execFileText(process.execPath, [scriptPath], {
          cwd: localDirectory,
        })
      } catch (error) {
        caughtError = error
      }

      expect(caughtError).toBeInstanceOf(Error)
      const message = (caughtError as Error).message
      expect(message).toContain("stdout-end")
      expect(message).toContain("stderr-end")
      expect(message).not.toContain("stdout-start")
      expect(message).not.toContain("stderr-start")
    } finally {
      await rm(localDirectory, { force: true, recursive: true })
    }
  })
})

// The GitHub Actions runners that execute `agent:check:integration` do not
// currently provide a working Docker runtime, so the harness cannot launch
// the sshd container that backs every test in this block. Re-enable the
// block by removing the `.skip` once the CI environment exposes Docker
// again (or once an alternative runtime such as Podman is wired up).
// oxlint-disable-next-line vitest/no-disabled-tests -- block is intentionally skipped until CI provides Docker; see AGENTS.md
describe.skip("Paratix integration", () => {
  beforeAll(async () => {
    originalHome = process.env.HOME
    integrationEnvironment = await createIntegrationEnvironment(
      resolve(import.meta.dirname, "../..")
    )
  })

  afterAll(async () => {
    restoreHomeEnvironmentVariable(originalHome)
    await integrationEnvironment?.cleanup()
  })

  beforeEach(() => {
    testHome = mkdtempSync(join(tmpdir(), "paratix-integration-home-"))
    process.env.HOME = testHome
    clearHostKeyCache()
    process.exitCode = 0
  })

  afterEach(async () => {
    clearHostKeyCache()
    process.exitCode = 0
    await rm(testHome, { force: true, recursive: true })
  })

  it("rejects unknown host keys when strict host key checking is enabled", async () => {
    const environment = getEnvironment()
    const ssh = new SshConnectionImpl(environment.host, {
      ports: [environment.primaryPort],
      privateKey: environment.clientPrivateKeyPath,
      strictHostKeyChecking: "yes",
      user: "paratix",
    })

    let primaryError: unknown
    try {
      await expect(ssh.connect()).rejects.toBeInstanceOf(HostKeyVerificationError)
    } catch (error) {
      primaryError = error
      throw error
    } finally {
      await runCleanupSteps([disconnectSshStep(ssh)], primaryError)
    }
  })

  it("connects with a pinned host key and passes probeSudo against the real server", async () => {
    const environment = getEnvironment()
    const ssh = await connectSsh([environment.primaryPort])
    try {
      await expect(ssh.probeSudo()).resolves.toBeUndefined()
      expect(ssh.getConnectionInfo().port).toBe(environment.primaryPort)
    } finally {
      ssh.disconnect()
    }
  })

  it("uploads and downloads files over real SFTP", async () => {
    const environment = getEnvironment()
    const ssh = await connectSsh([environment.primaryPort], {}, "root")
    const remoteBase = `/home/paratix/integration-${randomUUID()}`
    let localDirectory: string | undefined

    let primaryError: unknown
    try {
      localDirectory = mkdtempSync(join(tmpdir(), "paratix-sftp-"))
      const localUploadPath = join(localDirectory, "upload.txt")
      const localDownloadPath = join(localDirectory, "download.txt")
      const remoteUploadPath = `${remoteBase}/uploaded.txt`
      const remoteDownloadPath = `${remoteBase}/remote.txt`

      writeFileSync(localUploadPath, "upload-content\n", "utf8")
      await ssh.exec(`mkdir -p ${shellQuote(remoteBase)}`, { silent: true })
      await ssh.uploadFile(localUploadPath, remoteUploadPath)
      expect(await ssh.readFile(remoteUploadPath)).toBe("upload-content")

      await ssh.writeFile(remoteDownloadPath, "download-content\n", { mode: "0644" })
      await ssh.downloadFile(remoteDownloadPath, localDownloadPath)
      expect(await readFile(localDownloadPath, "utf8")).toBe("download-content\n")
    } catch (error) {
      primaryError = error
      throw error
    } finally {
      await runCleanupSteps(
        [
          removeRemoteDirectoryStep(ssh, remoteBase, "remove remote SFTP test directory"),
          disconnectSshStep(ssh),
          removeCreatedLocalDirectoryStep(() => localDirectory),
        ],
        primaryError
      )
    }
  })

  it("uploads and downloads unicode filenames and content over real SFTP", async () => {
    const environment = getEnvironment()
    const ssh = await connectSsh([environment.primaryPort], {}, "root")
    const remoteBase = `/home/paratix/integration-${randomUUID()}`
    const remoteDirectory = `${remoteBase}/über ordner`
    let localDirectory: string | undefined

    let primaryError: unknown
    try {
      localDirectory = mkdtempSync(join(tmpdir(), "paratix-sftp-unicode-"))
      const localUploadPath = join(localDirectory, unicodeFileName)
      const localDownloadPath = join(localDirectory, `download-${unicodeFileName}`)
      const remoteUploadPath = `${remoteDirectory}/${unicodeFileName}`
      const remoteDownloadPath = `${remoteDirectory}/下載-ß.txt`

      writeFileSync(localUploadPath, unicodeContent, "utf8")
      await ssh.exec(`mkdir -p ${shellQuote(remoteDirectory)}`, { silent: true })
      await ssh.uploadFile(localUploadPath, remoteUploadPath)
      expect(await ssh.readFile(remoteUploadPath)).toBe(unicodeContent.trimEnd())

      await ssh.writeFile(remoteDownloadPath, unicodeBlockContent, { mode: "0644" })
      await ssh.downloadFile(remoteDownloadPath, localDownloadPath)
      expect(await readFile(localDownloadPath, "utf8")).toBe(unicodeBlockContent)
    } catch (error) {
      primaryError = error
      throw error
    } finally {
      await runCleanupSteps(
        [
          removeRemoteDirectoryStep(ssh, remoteBase, "remove remote unicode SFTP test directory"),
          disconnectSshStep(ssh),
          removeCreatedLocalDirectoryStep(() => localDirectory),
        ],
        primaryError
      )
    }
  })

  it("uses sudo finalization and cleanup for non-root SFTP transfers", async () => {
    const environment = getEnvironment()
    const ssh = await connectSsh([environment.primaryPort])
    const remoteBase = `/root/non-root-sftp-${randomUUID()}`
    let localDirectory: string | undefined

    let primaryError: unknown
    try {
      localDirectory = mkdtempSync(join(tmpdir(), "paratix-sftp-non-root-"))
      const localUploadPath = join(localDirectory, "upload.txt")
      const localDownloadPath = join(localDirectory, "download.txt")
      const localFailedUploadPath = join(localDirectory, "failed-upload.txt")
      const remoteUploadPath = `${remoteBase}/uploaded.txt`
      const remoteDownloadPath = `${remoteBase}/download.txt`
      const missingParentUploadPath = `${remoteBase}/missing-parent/uploaded.txt`

      writeFileSync(localUploadPath, "non-root upload\n", "utf8")
      writeFileSync(localFailedUploadPath, "failed upload\n", "utf8")
      await ssh.exec(`mkdir -p ${shellQuote(remoteBase)} && chmod 0755 ${shellQuote(remoteBase)}`, {
        silent: true,
      })

      await ssh.uploadFile(localUploadPath, remoteUploadPath, { mode: "0640" })
      expect(await ssh.readFile(remoteUploadPath)).toBe("non-root upload")
      expect(await readRemoteStat(ssh, remoteUploadPath)).toStrictEqual({
        group: "root",
        mode: "640",
        owner: "root",
      })

      await ssh.exec(
        `printf %s ${shellQuote("sudo-only download\n")} > ${shellQuote(remoteDownloadPath)} && chmod 0600 ${shellQuote(remoteDownloadPath)} && chown root:root ${shellQuote(remoteDownloadPath)}`,
        { silent: true }
      )
      await ssh.downloadFile(remoteDownloadPath, localDownloadPath)
      expect(await readFile(localDownloadPath, "utf8")).toBe("sudo-only download\n")

      const temporaryUploadsBeforeFailure = await ssh.lines(
        "find /tmp -maxdepth 1 -user paratix -name 'paratix-upload.*' -print | sort"
      )
      await expect(ssh.uploadFile(localFailedUploadPath, missingParentUploadPath)).rejects.toThrow(
        "Command failed"
      )
      await expect(
        ssh.lines("find /tmp -maxdepth 1 -user paratix -name 'paratix-upload.*' -print | sort")
      ).resolves.toStrictEqual(temporaryUploadsBeforeFailure)
    } catch (error) {
      primaryError = error
      throw error
    } finally {
      await runCleanupSteps(
        [
          removeRemoteDirectoryStep(ssh, remoteBase, "remove remote non-root SFTP test directory"),
          disconnectSshStep(ssh),
          removeCreatedLocalDirectoryStep(() => localDirectory),
        ],
        primaryError
      )
    }
  })

  it("persists accept-new host keys and reconnects with strict known_hosts verification", async () => {
    const environment = getEnvironment()
    const acceptNewSsh = await connectWithConfig(createAcceptNewSshConfig(environment.primaryPort))

    let primaryError: unknown
    try {
      const knownHosts = await readFile(join(testHome, ".ssh", "known_hosts"), "utf8")
      expect(knownHosts).toContain(`[${environment.host}]:${String(environment.primaryPort)}`)
    } catch (error) {
      primaryError = error
      throw error
    } finally {
      await runCleanupSteps([disconnectSshStep(acceptNewSsh)], primaryError)
    }

    const strictSsh = await connectWithConfig(createKnownHostsSshConfig(environment.primaryPort))
    try {
      expect(await strictSsh.output("whoami")).toBe("paratix")
    } finally {
      strictSsh.disconnect()
    }
  })

  it("keeps accept-new known_hosts entries scoped to their SSH port", async () => {
    const environment = getEnvironment()
    const primarySsh = await connectWithConfig(createAcceptNewSshConfig(environment.primaryPort))
    let primaryError: unknown
    try {
      expect(primarySsh.getConnectionInfo().port).toBe(environment.primaryPort)
    } catch (error) {
      primaryError = error
      throw error
    } finally {
      await runCleanupSteps([disconnectSshStep(primarySsh)], primaryError)
    }

    const secondaryStrictSsh = new SshConnectionImpl(
      environment.host,
      createKnownHostsSshConfig(environment.secondaryPort)
    )
    let secondaryStrictPrimaryError: unknown
    try {
      await expect(secondaryStrictSsh.connect()).rejects.toBeInstanceOf(HostKeyVerificationError)
    } catch (error) {
      secondaryStrictPrimaryError = error
      throw error
    } finally {
      await runCleanupSteps([disconnectSshStep(secondaryStrictSsh)], secondaryStrictPrimaryError)
    }

    const secondaryAcceptNewSsh = await connectWithConfig(
      createAcceptNewSshConfig(environment.secondaryPort)
    )
    let secondaryAcceptNewPrimaryError: unknown
    try {
      expect(secondaryAcceptNewSsh.getConnectionInfo().port).toBe(environment.secondaryPort)
    } catch (error) {
      secondaryAcceptNewPrimaryError = error
      throw error
    } finally {
      await runCleanupSteps(
        [disconnectSshStep(secondaryAcceptNewSsh)],
        secondaryAcceptNewPrimaryError
      )
    }

    const secondaryKnownHostsSsh = await connectWithConfig(
      createKnownHostsSshConfig(environment.secondaryPort)
    )
    try {
      expect(await secondaryKnownHostsSsh.output("whoami")).toBe("paratix")
    } finally {
      secondaryKnownHostsSsh.disconnect()
    }
  })

  it("rejects changed host keys from known_hosts", async () => {
    const environment = getEnvironment()
    const hostLabel = `[${environment.host}]:${String(environment.primaryPort)}`
    const tamperedHostPublicKey = createTamperedHostPublicKey(environment.hostPublicKey)
    mkdirSync(join(testHome, ".ssh"), { recursive: true })
    writeFileSync(join(testHome, ".ssh", "known_hosts"), `${hostLabel} ${tamperedHostPublicKey}\n`)

    const ssh = new SshConnectionImpl(
      environment.host,
      createKnownHostsSshConfig(environment.primaryPort)
    )
    let primaryError: unknown
    try {
      await expect(ssh.connect()).rejects.toBeInstanceOf(HostKeyVerificationError)
    } catch (error) {
      primaryError = error
      throw error
    } finally {
      await runCleanupSteps([disconnectSshStep(ssh)], primaryError)
    }
  })

  it("reconnects successfully on a different configured port", async () => {
    const environment = getEnvironment()
    const ssh = await connectSsh([environment.primaryPort])

    try {
      ssh.removePort(environment.primaryPort)
      ssh.addPort(environment.secondaryPort)
      await ssh.reconnect()

      expect(ssh.getConnectionInfo().port).toBe(environment.secondaryPort)
      expect(await ssh.output("whoami")).toBe("root")
    } finally {
      ssh.disconnect()
    }
  })

  it("runs a real happy-path playbook against the integration server", async () => {
    const environment = getEnvironment()
    const remoteBase = `/root/integration-${randomUUID()}`
    const remoteApp = `${remoteBase}/app`
    const markerPath = `${remoteApp}/marker.txt`
    const ssh = await connectSsh([environment.primaryPort], {}, "root")
    let localDirectory: string | undefined

    let primaryError: unknown
    try {
      localDirectory = mkdtempSync(join(tmpdir(), "paratix-playbook-"))
      const localSourcePath = join(localDirectory, "source.txt")
      const localTemplatePath = join(localDirectory, "template.tmpl")

      writeFileSync(localSourcePath, "copied-from-local\n", "utf8")
      writeFileSync(localTemplatePath, "Hello {{NAME|raw}}\n", "utf8")

      const definition = server({
        env: { NAME: "integration" },
        host: environment.host,
        name: "integration-happy-path",
        run: [
          file.directory(remoteApp),
          file.copy(`${remoteApp}/source.txt`, localSourcePath),
          file.template(`${remoteApp}/template.txt`, localTemplatePath),
          command.shell(`printf '%s\\n' ready > ${shellQuote(markerPath)}`, {
            check: `test -f ${shellQuote(markerPath)}`,
            name: "create marker",
          }),
        ],
        ssh: createSshConfig([environment.primaryPort], {}, "root"),
      })

      await expect(runPlaybook(definition)).resolves.toBeUndefined()
      expect(process.exitCode).toBe(0)

      expect(await ssh.readFile(`${remoteApp}/source.txt`)).toBe("copied-from-local")
      expect(await ssh.readFile(`${remoteApp}/template.txt`)).toBe("Hello integration")
      expect(await ssh.readFile(markerPath)).toBe("ready")
    } catch (error) {
      primaryError = error
      throw error
    } finally {
      await runCleanupSteps(
        [
          removeRemoteDirectoryStep(ssh, remoteBase, "remove remote playbook test directory"),
          disconnectSshStep(ssh),
          removeCreatedLocalDirectoryStep(() => localDirectory),
        ],
        primaryError
      )
    }
  })

  it("runs the built apply CLI dry-run with a valid playbook against the integration server", async () => {
    const environment = getEnvironment()
    const packageDirectory = resolve(import.meta.dirname, "../..")
    const remoteBase = `/root/dist-cli-${randomUUID()}`
    const markerPath = `${remoteBase}/marker.txt`
    const distCliPath = resolve(packageDirectory, "dist/cli.js")
    const distIndexUrl = pathToFileURL(resolve(packageDirectory, "dist/index.js")).href
    const distModulesUrl = pathToFileURL(resolve(packageDirectory, "dist/modules/index.js")).href
    const markerCommand = `mkdir -p ${shellQuote(remoteBase)} && printf '%s\\n' changed > ${shellQuote(markerPath)}`
    const markerCheck = `test -f ${shellQuote(markerPath)}`
    const ssh = await connectSsh([environment.primaryPort], {}, "root")
    let localDirectory: string | undefined

    let primaryError: unknown
    try {
      localDirectory = mkdtempSync(join(tmpdir(), "paratix-dist-cli-playbook-"))
      const playbookPath = join(localDirectory, "playbook.mjs")

      writeFileSync(
        playbookPath,
        [
          `import { server } from ${JSON.stringify(distIndexUrl)}`,
          `import { command } from ${JSON.stringify(distModulesUrl)}`,
          "",
          "export default server({",
          "  name: 'dist-cli-integration',",
          `  host: ${JSON.stringify(environment.host)},`,
          "  ssh: {",
          `    expectedHostPublicKey: ${JSON.stringify(environment.hostPublicKey)},`,
          `    ports: [${String(environment.primaryPort)}],`,
          `    privateKey: ${JSON.stringify(environment.clientPrivateKeyPath)},`,
          "    strictHostKeyChecking: 'yes',",
          "    user: 'root',",
          "  },",
          "  run: [",
          `    command.shell(${JSON.stringify(markerCommand)}, {`,
          `      check: ${JSON.stringify(markerCheck)},`,
          "      name: 'create dist cli dry-run marker',",
          "    }),",
          "  ],",
          "})",
          "",
        ].join("\n")
      )

      const output = await execFileText(
        process.execPath,
        [distCliPath, "apply", playbookPath, "--dry-run"],
        {
          cwd: packageDirectory,
          env: { ...process.env, HOME: testHome },
        }
      )

      expect(output).toContain("dist-cli-integration")
      expect(output).toContain("create dist cli dry-run marker")
      expect(output).toContain("(dry-run)")
      await expect(ssh.test(`test -f ${shellQuote(markerPath)}`)).resolves.toBe(false)
    } catch (error) {
      primaryError = error
      throw error
    } finally {
      await runCleanupSteps(
        [
          removeRemoteDirectoryStep(ssh, remoteBase, "remove remote dist CLI test directory"),
          disconnectSshStep(ssh),
          removeCreatedLocalDirectoryStep(() => localDirectory),
        ],
        primaryError
      )
    }
  })

  it("runs the built apply CLI with dist modules and mutates the integration server", async () => {
    const environment = getEnvironment()
    const packageDirectory = resolve(import.meta.dirname, "../..")
    const remoteBase = `/root/dist-cli-apply-${randomUUID()}`
    const remoteApp = `${remoteBase}/app`
    const copiedPath = `${remoteApp}/copied.txt`
    const templatedPath = `${remoteApp}/templated.txt`
    const distCliPath = resolve(packageDirectory, "dist/cli.js")
    const distIndexUrl = pathToFileURL(resolve(packageDirectory, "dist/index.js")).href
    const distModulesUrl = pathToFileURL(resolve(packageDirectory, "dist/modules/index.js")).href
    const ssh = await connectSsh([environment.primaryPort], {}, "root")
    let localDirectory: string | undefined

    let primaryError: unknown
    try {
      localDirectory = mkdtempSync(join(tmpdir(), "paratix-dist-cli-apply-playbook-"))
      const localSourcePath = join(localDirectory, "source.txt")
      const localTemplatePath = join(localDirectory, "template.tmpl")
      const playbookPath = join(localDirectory, "playbook.mjs")

      writeFileSync(localSourcePath, "copied through dist CLI\n", "utf8")
      writeFileSync(localTemplatePath, "Rendered for {{TARGET|raw}}\n", "utf8")
      writeFileSync(
        playbookPath,
        [
          `import { server } from ${JSON.stringify(distIndexUrl)}`,
          `import { file } from ${JSON.stringify(distModulesUrl)}`,
          "",
          "export default server({",
          "  env: { TARGET: 'docker-sshd' },",
          "  name: 'dist-cli-apply-integration',",
          `  host: ${JSON.stringify(environment.host)},`,
          "  ssh: {",
          `    expectedHostPublicKey: ${JSON.stringify(environment.hostPublicKey)},`,
          `    ports: [${String(environment.primaryPort)}],`,
          `    privateKey: ${JSON.stringify(environment.clientPrivateKeyPath)},`,
          "    strictHostKeyChecking: 'yes',",
          "    user: 'root',",
          "  },",
          "  run: [",
          `    file.directory(${JSON.stringify(remoteApp)}, {`,
          "      mode: '0750',",
          "      owner: 'root:root',",
          "    }),",
          `    file.copy(${JSON.stringify(copiedPath)}, ${JSON.stringify(localSourcePath)}, {`,
          "      mode: '0640',",
          "      owner: 'root:root',",
          "    }),",
          `    file.template(${JSON.stringify(templatedPath)}, ${JSON.stringify(localTemplatePath)}, {`,
          "      mode: '0644',",
          "      owner: 'root:root',",
          "    }),",
          "  ],",
          "})",
          "",
        ].join("\n")
      )

      const firstOutput = await execFileText(
        process.execPath,
        [distCliPath, "apply", playbookPath],
        {
          cwd: packageDirectory,
          env: { ...process.env, HOME: testHome },
        }
      )

      expect(firstOutput).toContain("dist-cli-apply-integration")
      expect(firstOutput).toContain("file.copy")
      expect(await ssh.readFile(copiedPath)).toBe("copied through dist CLI")
      expect(await ssh.readFile(templatedPath)).toBe("Rendered for docker-sshd")
      expect(await readRemoteStat(ssh, remoteApp)).toStrictEqual({
        group: "root",
        mode: "750",
        owner: "root",
      })
      expect(await readRemoteStat(ssh, copiedPath)).toStrictEqual({
        group: "root",
        mode: "640",
        owner: "root",
      })

      const secondOutput = await execFileText(
        process.execPath,
        [distCliPath, "apply", playbookPath],
        {
          cwd: packageDirectory,
          env: { ...process.env, HOME: testHome },
        }
      )

      expect(secondOutput).toContain("dist-cli-apply-integration")
      expect(await ssh.readFile(copiedPath)).toBe("copied through dist CLI")
      expect(await ssh.readFile(templatedPath)).toBe("Rendered for docker-sshd")
    } catch (error) {
      primaryError = error
      throw error
    } finally {
      await runCleanupSteps(
        [
          removeRemoteDirectoryStep(ssh, remoteBase, "remove remote dist CLI apply test directory"),
          disconnectSshStep(ssh),
          removeCreatedLocalDirectoryStep(() => localDirectory),
        ],
        primaryError
      )
    }
  })

  it("converges file and command modules to verifiable remote state", async () => {
    const ssh = await connectSsh([getEnvironment().primaryPort], {}, "root")
    const remoteBase = `/root/integration-${randomUUID()}`
    const markerPath = `${remoteBase}/app/marker.txt`
    let localDirectory: string | undefined

    let primaryError: unknown
    try {
      localDirectory = mkdtempSync(join(tmpdir(), "paratix-modules-"))
      const localSourcePath = join(localDirectory, "source.txt")
      const localTemplatePath = join(localDirectory, "template.tmpl")

      writeFileSync(localSourcePath, "copied-from-integration\n", "utf8")
      writeFileSync(localTemplatePath, "Hello {{NAME|raw}}\n", "utf8")

      const directoryModule = file.directory(`${remoteBase}/app`, {
        mode: "0750",
        owner: "root:root",
      })
      const copyModule = file.copy(`${remoteBase}/app/source.txt`, localSourcePath, {
        mode: "0640",
        owner: "root:root",
      })
      const templateModule = file.template(`${remoteBase}/app/template.txt`, localTemplatePath, {
        mode: "0644",
        owner: "root:root",
      })
      const commandModule = command.shell(`printf '%s\\n' ready > ${shellQuote(markerPath)}`, {
        check: `test -f ${shellQuote(markerPath)}`,
        name: "create integration marker",
      })

      await expect(directoryModule.apply(ssh, emptyEnv)).resolves.toMatchObject({
        status: "changed",
      })
      await expect(copyModule.apply(ssh, emptyEnv)).resolves.toMatchObject({ status: "changed" })
      await expect(templateModule.apply(ssh, { NAME: "integration" })).resolves.toMatchObject({
        status: "changed",
      })
      await expect(commandModule.apply(ssh, emptyEnv)).resolves.toMatchObject({ status: "changed" })

      expect(await readRemoteStat(ssh, `${remoteBase}/app`)).toStrictEqual({
        group: "root",
        mode: "750",
        owner: "root",
      })
      expect(await readRemoteStat(ssh, `${remoteBase}/app/source.txt`)).toStrictEqual({
        group: "root",
        mode: "640",
        owner: "root",
      })
      expect(await ssh.readFile(`${remoteBase}/app/source.txt`)).toBe("copied-from-integration")
      expect(await ssh.readFile(`${remoteBase}/app/template.txt`)).toBe("Hello integration")
      expect(await ssh.readFile(markerPath)).toBe("ready")

      await expectModuleCheckOk(directoryModule, ssh)
      await expectModuleCheckOk(copyModule, ssh)
      await expectModuleCheckOk(templateModule, ssh, { NAME: "integration" })
      await expectModuleCheckOk(commandModule, ssh)
    } catch (error) {
      primaryError = error
      throw error
    } finally {
      await runCleanupSteps(
        [
          removeRemoteDirectoryStep(ssh, remoteBase, "remove remote module test directory"),
          disconnectSshStep(ssh),
          removeCreatedLocalDirectoryStep(() => localDirectory),
        ],
        primaryError
      )
    }
  })

  it("converges a numerically declared owner instead of reporting changed on every apply", async () => {
    const ssh = await connectSsh([getEnvironment().primaryPort], {}, "root")
    const remoteBase = `/root/integration-${randomUUID()}`
    const remoteDirectory = `${remoteBase}/numeric-owner`
    // 65532 has no passwd or group entry on the Ubuntu base image, so
    // `stat -c '%U %G'` answers UNKNOWN and only the numeric columns can
    // confirm that the declared ownership is already in place.
    const numericOwner = "65532:65532"

    let primaryError: unknown
    try {
      const directoryModule = file.directory(remoteDirectory, {
        mode: "0700",
        owner: numericOwner,
      })

      await expect(directoryModule.apply(ssh, emptyEnv)).resolves.toMatchObject({
        status: "changed",
      })

      expect(await ssh.output(`stat -c '%a %u %g' ${shellQuote(remoteDirectory)}`)).toContain(
        "700 65532 65532"
      )

      // The second apply must converge: before the numeric comparison this
      // reported "changed" forever and re-fired the recipe's signals.
      await expect(directoryModule.apply(ssh, emptyEnv)).resolves.toMatchObject({ status: "ok" })
      await expectModuleCheckOk(directoryModule, ssh)
    } catch (error) {
      primaryError = error
      throw error
    } finally {
      await runCleanupSteps(
        [
          removeRemoteDirectoryStep(ssh, remoteBase, "remove remote numeric owner test directory"),
          disconnectSshStep(ssh),
        ],
        primaryError
      )
    }
  })

  it("converges unicode file, template, and block modules to verifiable remote state", async () => {
    const ssh = await connectSsh([getEnvironment().primaryPort], {}, "root")
    const remoteBase = `/root/integration-${randomUUID()}-äöü`
    const remoteDirectory = `${remoteBase}/über ordner`
    const remoteCopyPath = `${remoteDirectory}/${unicodeFileName}`
    const remoteTemplatePath = `${remoteDirectory}/結果-template.txt`
    const remoteBlockPath = `${remoteDirectory}/konfiguration ü.txt`
    let localDirectory: string | undefined

    let primaryError: unknown
    try {
      localDirectory = mkdtempSync(join(tmpdir(), "paratix-unicode-modules-"))
      const localSourcePath = join(localDirectory, unicodeFileName)
      const localTemplatePath = join(localDirectory, unicodeTemplateName)

      writeFileSync(localSourcePath, unicodeContent, "utf8")
      writeFileSync(localTemplatePath, "Hallo {{name|raw}} aus {{city|raw}}", "utf8")
      await ssh.exec(`mkdir -p ${shellQuote(remoteDirectory)}`, { silent: true })
      await ssh.writeFile(remoteBlockPath, "vorher\n", { mode: "0644" })

      const directoryModule = file.directory(remoteDirectory, {
        mode: "0750",
        owner: "root:root",
      })
      const copyModule = file.copy(remoteCopyPath, localSourcePath, {
        mode: "0640",
        owner: "root:root",
      })
      const templateModule = file.template(remoteTemplatePath, localTemplatePath, {
        mode: "0644",
        owner: "root:root",
      })
      const blockModule = file.block(remoteBlockPath, {
        content: unicodeBlockContent,
        name: "grüße-block",
      })

      await expect(directoryModule.apply(ssh, emptyEnv)).resolves.toMatchObject({
        status: "changed",
      })
      await expect(copyModule.apply(ssh, emptyEnv)).resolves.toMatchObject({ status: "changed" })
      await expect(
        templateModule.apply(ssh, { city: "München", name: "Jörg" })
      ).resolves.toMatchObject({
        status: "changed",
      })
      await expect(blockModule.apply(ssh, emptyEnv)).resolves.toMatchObject({ status: "changed" })

      expect(await ssh.readFile(remoteCopyPath)).toBe(unicodeContent.trimEnd())
      expect(await readRemoteStat(ssh, remoteCopyPath)).toStrictEqual({
        group: "root",
        mode: "640",
        owner: "root",
      })
      expect(await ssh.readFile(remoteTemplatePath)).toBe("Hallo Jörg aus München")
      expect(await ssh.readFile(remoteBlockPath)).toContain("こんにちは")
      expect(await ssh.readFile(remoteBlockPath)).toContain("Привет")
      expect(await ssh.readFile(remoteBlockPath)).toContain("# BEGIN paratix: grüße-block")

      await expectModuleCheckOk(directoryModule, ssh)
      await expectModuleCheckOk(copyModule, ssh)
      await expectModuleCheckOk(templateModule, ssh, { city: "München", name: "Jörg" })
      await expectModuleCheckOk(blockModule, ssh)
    } catch (error) {
      primaryError = error
      throw error
    } finally {
      await runCleanupSteps(
        [
          removeRemoteDirectoryStep(ssh, remoteBase, "remove remote unicode module test directory"),
          disconnectSshStep(ssh),
          removeCreatedLocalDirectoryStep(() => localDirectory),
        ],
        primaryError
      )
    }
  })

  it("downloads artifacts over a real server and verifies remote state for download.url and download.large", async () => {
    const ssh = await connectSsh([getEnvironment().primaryPort], {}, "root")
    const remoteBase = `/root/integration-${randomUUID()}`
    const httpDirectory = `${remoteBase}/http`
    const downloadsDirectory = `${remoteBase}/downloads`
    const urlArtifactContent = "integration-url-download\n"
    const largeArtifactContent = "integration-large-download\n"
    const urlArtifactSha256 = createHash("sha256").update(urlArtifactContent).digest("hex")
    const largeArtifactSha256 = createHash("sha256").update(largeArtifactContent).digest("hex")
    const port = allocateHttpPort()
    const urlArtifactRemotePath = `${downloadsDirectory}/artifact-url.txt`
    const largeArtifactRemotePath = `${downloadsDirectory}/artifact-large.txt`
    const urlArtifactUrl = `http://127.0.0.1:${String(port)}/artifact-url.txt`
    const largeArtifactUrl = `http://127.0.0.1:${String(port)}/artifact-large.txt`
    const urlModule = download.url(urlArtifactRemotePath, urlArtifactUrl, {
      allowInsecureHttp: true,
      group: "root",
      mode: "0600",
      owner: "root",
      sha256: urlArtifactSha256,
    })
    const largeModule = download.large(largeArtifactRemotePath, largeArtifactUrl, {
      allowInsecureHttp: true,
      group: "root",
      mode: "0640",
      owner: "root",
      sha256: largeArtifactSha256,
    })
    const largeFlagName = buildLargeDownloadFlagName({
      destination: largeArtifactRemotePath,
      url: largeArtifactUrl,
    })

    let primaryError: unknown
    try {
      await ssh.exec(`mkdir -p ${shellQuote(httpDirectory)} ${shellQuote(downloadsDirectory)}`, {
        silent: true,
      })
      await ssh.writeFile(`${httpDirectory}/artifact-url.txt`, urlArtifactContent, { mode: "0644" })
      await ssh.writeFile(`${httpDirectory}/artifact-large.txt`, largeArtifactContent, {
        mode: "0644",
      })
      await startRemoteHttpServer(ssh, httpDirectory, port)
      await waitForRemoteHttpServer(ssh, urlArtifactUrl)

      await expect(urlModule.apply(ssh, emptyEnv)).resolves.toMatchObject({ status: "changed" })
      await expect(largeModule.apply(ssh, emptyEnv)).resolves.toMatchObject({ status: "changed" })

      expect(await ssh.readFile(urlArtifactRemotePath)).toBe("integration-url-download")
      expect(await readRemoteStat(ssh, urlArtifactRemotePath)).toStrictEqual({
        group: "root",
        mode: "600",
        owner: "root",
      })
      expect(await ssh.readFile(largeArtifactRemotePath)).toBe("integration-large-download")
      expect(await readRemoteStat(ssh, largeArtifactRemotePath)).toStrictEqual({
        group: "root",
        mode: "640",
        owner: "root",
      })
      expect(await ssh.test(`[ -f /var/lib/paratix/flags/${shellQuote(largeFlagName)} ]`)).toBe(
        true
      )

      await expectModuleCheckOk(urlModule, ssh)
      await expectModuleCheckOk(largeModule, ssh)
    } catch (error) {
      primaryError = error
      throw error
    } finally {
      await runCleanupSteps(
        [
          {
            name: "stop remote HTTP server",
            async run() {
              await stopRemoteHttpServer(ssh, port)
            },
          },
          removeRemoteDirectoryStep(ssh, remoteBase, "remove remote download test directory"),
          disconnectSshStep(ssh),
        ],
        primaryError
      )
    }
  })
})
