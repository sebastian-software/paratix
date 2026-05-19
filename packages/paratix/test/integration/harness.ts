/* eslint-disable max-lines -- integration harness keeps Docker lifecycle helpers together */
import { execFile } from "node:child_process"
import { randomUUID } from "node:crypto"
import { chmod, mkdir, mkdtemp, readFile, rm } from "node:fs/promises"
import net from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"

const DOCKER_IMAGE_TAG_PREFIX = "paratix-integration-sshd"
const DOCKER_RESOURCE_LABEL_PREFIX = "com.sebastian-software.paratix.integration"
const DOCKER_RESOURCE_MANAGED_LABEL = `${DOCKER_RESOURCE_LABEL_PREFIX}.managed=true`
const DOCKER_RESOURCE_ID_LABEL = `${DOCKER_RESOURCE_LABEL_PREFIX}.id`
const HOST = "127.0.0.1"
const TEN = "0123456789".length
const EIGHT = "12345678".length
const KILOBYTE = 1024
const MEGABYTE = KILOBYTE * KILOBYTE
const TEN_MEGABYTES = TEN * MEGABYTE
const COMMAND_FAILURE_OUTPUT_LIMIT = EIGHT * KILOBYTE
const COMMAND_MAX_BUFFER = TEN_MEGABYTES
const DEFAULT_COMMAND_TIMEOUT_MS = 30_000
const SHORT_COMMAND_TIMEOUT_MS = 15_000
const CLEANUP_COMMAND_TIMEOUT_MS = 60_000
const LONG_COMMAND_TIMEOUT_MS = 150_000
const PRIVATE_KEY_MODE = 0o600
const SSH_HOME_MODE = 0o700
const SOCKET_TIMEOUT = 1000
const SSH_POLL_INTERVAL = 250
const SSH_READY_TIMEOUT = 30_000

export type IntegrationEnvironment = {
  cleanup: () => Promise<void>
  clientPrivateKeyPath: string
  containerName: string
  dockerImageTag: string
  host: string
  hostPublicKey: string
  primaryPort: number
  secondaryPort: number
  workspaceHome: string
}

type CommandOptions = {
  cwd?: string
  timeoutMs?: number
}

type CommandResult = {
  stderr: string
  stdout: string
}

type CommandRunner = (
  command: string,
  commandArguments: string[],
  options?: CommandOptions
) => Promise<string>

type RuntimeAvailabilityOptions = {
  env?: NodeJS.ProcessEnv
  platform?: NodeJS.Platform
  run?: CommandRunner
}

type DockerResourceMetadata = {
  containerName: string
  dockerImageTag: string
  labels: string[]
}

export function restoreHomeEnvironmentVariable(originalHome: string | undefined): void {
  if (originalHome === undefined) {
    delete process.env.HOME
    return
  }

  process.env.HOME = originalHome
}

class CommandExecutionError extends Error {
  public readonly stderr: string
  public readonly stdout: string

  public constructor(
    message: string,
    streams: { stderr: string; stdout: string },
    options: { cause: Error }
  ) {
    super(message, options)
    this.name = "CommandExecutionError"
    this.stderr = streams.stderr
    this.stdout = streams.stdout
  }
}

function tailOutput(output: string): string {
  if (output.length <= COMMAND_FAILURE_OUTPUT_LIMIT) return output
  return output.slice(-COMMAND_FAILURE_OUTPUT_LIMIT)
}

function formatCommandFailureStream(label: "stderr" | "stdout", output: string): string {
  const tail = tailOutput(output).trim()
  if (tail.length === 0) return ""
  return `${label}:\n${tail}`
}

function formatCommandFailureStreams(streams: { stderr: string; stdout: string }): string {
  return [
    formatCommandFailureStream("stdout", streams.stdout),
    formatCommandFailureStream("stderr", streams.stderr),
  ]
    .filter((details) => details.length > 0)
    .join("\n")
}

async function execFileText(
  command: string,
  commandArguments: string[],
  options: CommandOptions
): Promise<CommandResult> {
  return new Promise<CommandResult>((resolve, reject) => {
    execFile(
      command,
      commandArguments,
      {
        cwd: options.cwd,
        encoding: "utf8",
        killSignal: "SIGTERM",
        maxBuffer: COMMAND_MAX_BUFFER,
        timeout: options.timeoutMs ?? DEFAULT_COMMAND_TIMEOUT_MS,
      },
      (error, stdout, stderr) => {
        if (error != null) {
          reject(
            new CommandExecutionError(
              "Command execution failed",
              {
                stderr,
                stdout,
              },
              { cause: error }
            )
          )
          return
        }
        resolve({ stderr, stdout })
      }
    )
  })
}

function getCommandFailureDetails(error: unknown): string {
  if (!(error instanceof CommandExecutionError)) return ""
  return formatCommandFailureStreams({ stderr: error.stderr, stdout: error.stdout })
}

async function runCommand(
  command: string,
  commandArguments: string[],
  options: CommandOptions = {}
): Promise<string> {
  try {
    const result = await execFileText(command, commandArguments, options)
    return result.stdout.trim()
  } catch (error) {
    const details = getCommandFailureDetails(error)
    const suffix = details.length > 0 ? `\n${details}` : ""
    if (error instanceof Error) {
      throw new TypeError(`Command failed: ${command} ${commandArguments.join(" ")}${suffix}`, {
        cause: error,
      })
    }
    throw new Error(`Command failed: ${command} ${commandArguments.join(" ")}${suffix}`, {
      cause: error,
    })
  }
}

async function startColima(run: CommandRunner): Promise<void> {
  try {
    await run("colima", ["start"], { timeoutMs: LONG_COMMAND_TIMEOUT_MS })
  } catch (startError) {
    throw new Error(
      "Integration tests require Colima. `colima` is installed, but the explicit opt-in start failed.",
      { cause: startError }
    )
  }
}

async function ensureDockerIsAvailable(run: CommandRunner): Promise<void> {
  try {
    await run("docker", ["info"], { timeoutMs: DEFAULT_COMMAND_TIMEOUT_MS })
  } catch (error) {
    throw new Error("Integration tests require a reachable Docker runtime.", { cause: error })
  }
}

function shouldStartColima(environment: NodeJS.ProcessEnv): boolean {
  return environment.PARATIX_INTEGRATION_START_COLIMA === "true"
}

function createColimaNotRunningError(): Error {
  return new Error(
    "Integration tests require a running Colima runtime. Start Colima manually or set PARATIX_INTEGRATION_START_COLIMA=true to allow the integration harness to start it."
  )
}

async function ensureColimaIsAvailable(
  environment: NodeJS.ProcessEnv,
  run: CommandRunner
): Promise<void> {
  try {
    await run("which", ["colima"], { timeoutMs: SHORT_COMMAND_TIMEOUT_MS })
  } catch (error) {
    throw new Error(
      "Integration tests require Colima, but `colima` was not found in PATH. Install Colima and retry.",
      { cause: error }
    )
  }

  try {
    const status = await run("colima", ["status"], { timeoutMs: SHORT_COMMAND_TIMEOUT_MS })
    if (/running/iv.test(status)) return
  } catch {
    if (shouldStartColima(environment)) {
      await startColima(run)
      return
    }
    throw createColimaNotRunningError()
  }

  if (!shouldStartColima(environment)) throw createColimaNotRunningError()
  await startColima(run)
}

export async function ensureIntegrationRuntimeIsAvailable(
  options: RuntimeAvailabilityOptions = {}
): Promise<void> {
  const environment = options.env ?? process.env
  const platform = options.platform ?? process.platform
  const run = options.run ?? runCommand

  const isCiRuntime = environment.CI === "true"
  if (isCiRuntime || platform !== "darwin") {
    await ensureDockerIsAvailable(run)
    return
  }

  await ensureColimaIsAvailable(environment, run)

  try {
    await run("docker", ["info"], { timeoutMs: DEFAULT_COMMAND_TIMEOUT_MS })
  } catch (error) {
    throw new Error(
      "Colima is available, but Docker is not reachable through the active Colima runtime.",
      { cause: error }
    )
  }
}

async function canConnectToPort(host: string, port: number): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    const socket = net.connect({ host, port })
    socket.setTimeout(SOCKET_TIMEOUT)
    socket.once("connect", () => {
      socket.destroy()
      resolve(true)
    })
    const fail = (): void => {
      socket.destroy()
      resolve(false)
    }
    socket.once("error", fail)
    socket.once("timeout", fail)
  })
}

async function sleep(delayMs: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, delayMs)
  })
}

async function waitForTcpPort(host: string, port: number, timeoutMs: number): Promise<void> {
  const connected = await canConnectToPort(host, port)
  if (connected) return
  if (timeoutMs <= SSH_POLL_INTERVAL) {
    throw new Error(`Timed out waiting for SSH on ${host}:${port}`)
  }
  await sleep(SSH_POLL_INTERVAL)
  await waitForTcpPort(host, port, timeoutMs - SSH_POLL_INTERVAL)
}

function parseDockerPort(output: string): number {
  const match = /:(?<port>\d+)\s*$/v.exec(output)
  const port = match?.groups?.port
  if (port == null) throw new Error(`Unexpected docker port output: ${output}`)
  return Number(port)
}

export function createDockerResourceMetadata(resourceId = randomUUID()): DockerResourceMetadata {
  return {
    containerName: `paratix-integration-${resourceId}`,
    dockerImageTag: `${DOCKER_IMAGE_TAG_PREFIX}:${resourceId}`,
    labels: [DOCKER_RESOURCE_MANAGED_LABEL, `${DOCKER_RESOURCE_ID_LABEL}=${resourceId}`],
  }
}

function createDockerLabelArguments(labels: string[]): string[] {
  return labels.flatMap((label) => ["--label", label])
}

async function prepareWorkspaceHome(): Promise<string> {
  const workspaceHome = await mkdtemp(join(tmpdir(), "paratix-integration-home-"))
  await mkdir(join(workspaceHome, ".ssh"), { mode: SSH_HOME_MODE, recursive: true })
  return workspaceHome
}

async function generateClientKeyPair(clientPrivateKeyPath: string): Promise<string> {
  await runCommand(
    "ssh-keygen",
    ["-t", "ed25519", "-N", "", "-f", clientPrivateKeyPath, "-C", "paratix-integration"],
    { timeoutMs: SHORT_COMMAND_TIMEOUT_MS }
  )
  await chmod(clientPrivateKeyPath, PRIVATE_KEY_MODE)
  const publicKey = await readFile(`${clientPrivateKeyPath}.pub`, "utf8")
  return publicKey.trim()
}

function createEnvironmentResult(parameters: {
  cleanup: () => Promise<void>
  clientPrivateKeyPath: string
  containerName: string
  dockerImageTag: string
  hostPublicKey: string
  primaryPort: number
  secondaryPort: number
  workspaceHome: string
}): IntegrationEnvironment {
  return {
    cleanup: parameters.cleanup,
    clientPrivateKeyPath: parameters.clientPrivateKeyPath,
    containerName: parameters.containerName,
    dockerImageTag: parameters.dockerImageTag,
    host: HOST,
    hostPublicKey: parameters.hostPublicKey,
    primaryPort: parameters.primaryPort,
    secondaryPort: parameters.secondaryPort,
    workspaceHome: parameters.workspaceHome,
  }
}

function createCleanup(
  containerName: string,
  dockerImageTag: string,
  workspaceHome: string
): () => Promise<void> {
  return async (): Promise<void> => {
    try {
      await runCommand("docker", ["rm", "-f", containerName], {
        timeoutMs: CLEANUP_COMMAND_TIMEOUT_MS,
      })
    } catch {
      // Best-effort cleanup.
    }
    try {
      await runCommand("docker", ["image", "rm", "-f", dockerImageTag], {
        timeoutMs: CLEANUP_COMMAND_TIMEOUT_MS,
      })
    } catch {
      // Best-effort cleanup.
    }
    await rm(workspaceHome, { force: true, recursive: true })
  }
}

async function createEnvironmentResources(packageDirectory: string): Promise<{
  cleanup: () => Promise<void>
  clientPrivateKeyPath: string
  containerName: string
  dockerImageTag: string
  dockerLabels: string[]
  workspaceHome: string
}> {
  const workspaceHome = await prepareWorkspaceHome()
  const { containerName, dockerImageTag, labels: dockerLabels } = createDockerResourceMetadata()
  const cleanup = createCleanup(containerName, dockerImageTag, workspaceHome)
  const clientPrivateKeyPath = join(workspaceHome, ".ssh", "client_ed25519")
  try {
    const clientPublicKey = await generateClientKeyPair(clientPrivateKeyPath)
    await buildIntegrationImage({
      clientPublicKey,
      dockerImageTag,
      labels: dockerLabels,
      packageDirectory,
    })
  } catch (error) {
    try {
      await cleanup()
    } catch {
      // Preserve the setup failure; cleanup is best-effort on this path.
    }
    throw error
  }
  return {
    cleanup,
    clientPrivateKeyPath,
    containerName,
    dockerImageTag,
    dockerLabels,
    workspaceHome,
  }
}

async function buildIntegrationImage(parameters: {
  clientPublicKey: string
  dockerImageTag: string
  labels: string[]
  packageDirectory: string
}): Promise<void> {
  await runCommand(
    "docker",
    [
      "build",
      ...createDockerLabelArguments(parameters.labels),
      "--build-arg",
      `CLIENT_PUBLIC_KEY=${parameters.clientPublicKey}`,
      "-t",
      parameters.dockerImageTag,
      "-f",
      "test/integration/docker/Dockerfile",
      ".",
    ],
    {
      cwd: parameters.packageDirectory,
      timeoutMs: LONG_COMMAND_TIMEOUT_MS,
    }
  )
}

async function startIntegrationContainer(
  containerName: string,
  dockerImageTag: string,
  labels: string[]
): Promise<void> {
  await runCommand(
    "docker",
    [
      "run",
      "--detach",
      "--name",
      containerName,
      ...createDockerLabelArguments(labels),
      "--publish",
      `${HOST}::22`,
      "--publish",
      `${HOST}::2222`,
      dockerImageTag,
    ],
    { timeoutMs: DEFAULT_COMMAND_TIMEOUT_MS }
  )
}

async function readPublishedPorts(
  containerName: string
): Promise<{ primaryPort: number; secondaryPort: number }> {
  const primaryPort = parseDockerPort(
    await runCommand("docker", ["port", containerName, "22/tcp"], {
      timeoutMs: SHORT_COMMAND_TIMEOUT_MS,
    })
  )
  const secondaryPort = parseDockerPort(
    await runCommand("docker", ["port", containerName, "2222/tcp"], {
      timeoutMs: SHORT_COMMAND_TIMEOUT_MS,
    })
  )
  return { primaryPort, secondaryPort }
}

async function readHostPublicKey(containerName: string): Promise<string> {
  return runCommand("docker", ["exec", containerName, "cat", "/etc/ssh/ssh_host_ed25519_key.pub"], {
    timeoutMs: SHORT_COMMAND_TIMEOUT_MS,
  })
}

export async function createIntegrationEnvironment(
  packageDirectory: string
): Promise<IntegrationEnvironment> {
  await ensureIntegrationRuntimeIsAvailable()
  const {
    cleanup,
    clientPrivateKeyPath,
    containerName,
    dockerImageTag,
    dockerLabels,
    workspaceHome,
  } = await createEnvironmentResources(packageDirectory)

  try {
    await startIntegrationContainer(containerName, dockerImageTag, dockerLabels)
    const { primaryPort, secondaryPort } = await readPublishedPorts(containerName)
    await waitForTcpPort(HOST, primaryPort, SSH_READY_TIMEOUT)
    await waitForTcpPort(HOST, secondaryPort, SSH_READY_TIMEOUT)
    const hostPublicKey = await readHostPublicKey(containerName)
    return createEnvironmentResult({
      cleanup,
      clientPrivateKeyPath,
      containerName,
      dockerImageTag,
      hostPublicKey,
      primaryPort,
      secondaryPort,
      workspaceHome,
    })
  } catch (error) {
    await cleanup()
    throw error
  }
}
