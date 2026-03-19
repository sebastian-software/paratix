import { execFile } from "node:child_process"
import { chmodSync } from "node:fs"
import { mkdir, mkdtemp, rm } from "node:fs/promises"
import net from "node:net"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"

const DOCKER_IMAGE_TAG = "paratix-integration-sshd:latest"
const HOST = "127.0.0.1"
const TEN = "0123456789".length
const KILOBYTE = 1024
const MEGABYTE = KILOBYTE * KILOBYTE
const TEN_MEGABYTES = TEN * MEGABYTE
const COMMAND_MAX_BUFFER = TEN_MEGABYTES
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
}

type CommandResult = {
  stderr: string
  stdout: string
}

class CommandExecutionError extends Error {
  public readonly stderr: string

  public constructor(message: string, stderr: string, options: { cause: Error }) {
    super(message, options)
    this.name = "CommandExecutionError"
    this.stderr = stderr
  }
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
        maxBuffer: COMMAND_MAX_BUFFER,
      },
      (error, stdout, stderr) => {
        if (error != null) {
          reject(new CommandExecutionError("Command execution failed", stderr, { cause: error }))
          return
        }
        resolve({ stderr, stdout })
      }
    )
  })
}

function getCommandFailureDetails(error: unknown): string {
  if (!(error instanceof CommandExecutionError)) return ""
  return error.stderr.trim()
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

async function startColima(): Promise<void> {
  try {
    await runCommand("colima", ["start"])
  } catch (startError) {
    throw new Error(
      "Integration tests require Colima. `colima` is installed, but it could not be started automatically.",
      { cause: startError }
    )
  }
}

async function ensureDockerIsAvailable(): Promise<void> {
  try {
    await runCommand("docker", ["info"])
  } catch (error) {
    throw new Error("Integration tests require a reachable Docker runtime.", { cause: error })
  }
}

async function ensureColimaIsAvailable(): Promise<void> {
  try {
    await runCommand("which", ["colima"])
  } catch (error) {
    throw new Error(
      "Integration tests require Colima, but `colima` was not found in PATH. Install Colima and retry.",
      { cause: error }
    )
  }

  try {
    const status = await runCommand("colima", ["status"])
    if (!/running/iv.test(status)) {
      await runCommand("colima", ["start"])
    }
  } catch {
    await startColima()
  }
}

async function ensureIntegrationRuntimeIsAvailable(): Promise<void> {
  const isCiRuntime = process.env.CI === "true"
  if (isCiRuntime || process.platform !== "darwin") {
    await ensureDockerIsAvailable()
    return
  }

  await ensureColimaIsAvailable()

  try {
    await runCommand("docker", ["info"])
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

async function prepareWorkspaceHome(): Promise<string> {
  const workspaceHome = await mkdtemp(join(tmpdir(), "paratix-integration-home-"))
  await mkdir(join(workspaceHome, ".ssh"), { mode: SSH_HOME_MODE, recursive: true })
  return workspaceHome
}

function createEnvironmentResult(parameters: {
  cleanup: () => Promise<void>
  clientPrivateKeyPath: string
  containerName: string
  hostPublicKey: string
  primaryPort: number
  secondaryPort: number
  workspaceHome: string
}): IntegrationEnvironment {
  return {
    cleanup: parameters.cleanup,
    clientPrivateKeyPath: parameters.clientPrivateKeyPath,
    containerName: parameters.containerName,
    dockerImageTag: DOCKER_IMAGE_TAG,
    host: HOST,
    hostPublicKey: parameters.hostPublicKey,
    primaryPort: parameters.primaryPort,
    secondaryPort: parameters.secondaryPort,
    workspaceHome: parameters.workspaceHome,
  }
}

function createCleanup(containerName: string, workspaceHome: string): () => Promise<void> {
  return async (): Promise<void> => {
    try {
      await runCommand("docker", ["rm", "-f", containerName])
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
  workspaceHome: string
}> {
  const workspaceHome = await prepareWorkspaceHome()
  const containerName = `paratix-integration-${Date.now()}`
  const clientPrivateKeyPath = resolve(packageDirectory, "test/integration/fixtures/client_ed25519")
  chmodSync(clientPrivateKeyPath, PRIVATE_KEY_MODE)
  await buildIntegrationImage(packageDirectory)
  const cleanup = createCleanup(containerName, workspaceHome)
  return { cleanup, clientPrivateKeyPath, containerName, workspaceHome }
}

async function buildIntegrationImage(packageDirectory: string): Promise<void> {
  await runCommand(
    "docker",
    ["build", "-t", DOCKER_IMAGE_TAG, "-f", "test/integration/docker/Dockerfile", "."],
    {
      cwd: packageDirectory,
    }
  )
}

async function startIntegrationContainer(containerName: string): Promise<void> {
  await runCommand("docker", [
    "run",
    "--detach",
    "--name",
    containerName,
    "--publish",
    `${HOST}::22`,
    "--publish",
    `${HOST}::2222`,
    DOCKER_IMAGE_TAG,
  ])
}

async function readPublishedPorts(
  containerName: string
): Promise<{ primaryPort: number; secondaryPort: number }> {
  const primaryPort = parseDockerPort(await runCommand("docker", ["port", containerName, "22/tcp"]))
  const secondaryPort = parseDockerPort(
    await runCommand("docker", ["port", containerName, "2222/tcp"])
  )
  return { primaryPort, secondaryPort }
}

async function readHostPublicKey(containerName: string): Promise<string> {
  return runCommand("docker", ["exec", containerName, "cat", "/etc/ssh/ssh_host_ed25519_key.pub"])
}

export async function createIntegrationEnvironment(
  packageDirectory: string
): Promise<IntegrationEnvironment> {
  await ensureIntegrationRuntimeIsAvailable()
  const { cleanup, clientPrivateKeyPath, containerName, workspaceHome } =
    await createEnvironmentResources(packageDirectory)

  try {
    await startIntegrationContainer(containerName)
    const { primaryPort, secondaryPort } = await readPublishedPorts(containerName)
    await waitForTcpPort(HOST, primaryPort, SSH_READY_TIMEOUT)
    await waitForTcpPort(HOST, secondaryPort, SSH_READY_TIMEOUT)
    const hostPublicKey = await readHostPublicKey(containerName)
    return createEnvironmentResult({
      cleanup,
      clientPrivateKeyPath,
      containerName,
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
