/* eslint-disable max-lines -- integration harness keeps Docker lifecycle helpers together */
import { execFile, spawn } from "node:child_process"
import { randomBytes, randomUUID } from "node:crypto"
import { access, chmod, mkdir, mkdtemp, readFile, rm } from "node:fs/promises"
import net from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"

const DOCKER_IMAGE_TAG_PREFIX = "paratix-integration-sshd"
const DOCKER_RESOURCE_LABEL_PREFIX = "com.sebastian-software.paratix.integration"
const DOCKER_RESOURCE_MANAGED_LABEL = `${DOCKER_RESOURCE_LABEL_PREFIX}.managed=true`
const DOCKER_RESOURCE_ID_LABEL = `${DOCKER_RESOURCE_LABEL_PREFIX}.id`
const HOST = "127.0.0.1"
const PRIMARY_SSH_PORT = 22
const SECONDARY_SSH_PORT = 2222
const PASSWORD_RANDOM_BYTES = 24
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

const PROFILE_PORTS = {
  ecdsaPort: 2228,
  ed25519Port: 2226,
  forwardingPort: 2225,
  keyboardInteractivePort: 2229,
  maxSessionsPort: 2224,
  passwordPort: 2223,
  rsaPort: 2227,
} as const

type PublishedPorts = {
  primaryPort: number
  secondaryPort: number
} & Record<keyof typeof PROFILE_PORTS, number>

export type IntegrationEnvironment = PublishedPorts & {
  cleanup: () => Promise<void>
  clientPrivateKeyPath: string
  containerName: string
  dockerImageTag: string
  host: string
  hostPublicKey: string
  hostPublicKeys: Record<"ecdsa" | "ed25519" | "rsa", string>
  password: string
  workspaceHome: string
}

type CommandOptions = {
  cwd?: string
  env?: NodeJS.ProcessEnv
  input?: string
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
    const child = execFile(
      command,
      commandArguments,
      {
        cwd: options.cwd,
        encoding: "utf8",
        env: options.env,
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
    if (options.input != null) {
      child.stdin?.on("error", () => {
        // The callback owns command failures, including an early closed stdin.
      })
      child.stdin?.end(options.input)
    }
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
    throw createDockerNotReachableError(error)
  }
}

function shouldStartColima(environment: NodeJS.ProcessEnv): boolean {
  return environment.PARATIX_INTEGRATION_START_COLIMA === "true"
}

function createDockerNotReachableError(cause: unknown): Error {
  return new Error("Integration tests require a reachable Docker runtime.", { cause })
}

function createColimaNotRunningError(): Error {
  return new Error(
    "Integration tests require a running Colima runtime. Start Colima manually or set PARATIX_INTEGRATION_START_COLIMA=true to allow the integration harness to start it."
  )
}

function isColimaRunningStatus(status: string): boolean {
  return /^Status:\s*Running$/imv.test(status) || /^Running$/imv.test(status.trim())
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
    if (isColimaRunningStatus(status)) return
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
  try {
    await ensureDockerIsAvailable(run)
    return
  } catch (dockerError) {
    if (isCiRuntime || platform !== "darwin") throw dockerError
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
      ...Object.values(PROFILE_PORTS).flatMap((port) => ["--publish", `${HOST}::${port}`]),
      dockerImageTag,
    ],
    { timeoutMs: DEFAULT_COMMAND_TIMEOUT_MS }
  )
}

async function readPublishedPorts(containerName: string): Promise<PublishedPorts> {
  const readPort = async (port: number): Promise<number> =>
    parseDockerPort(await runCommand("docker", ["port", containerName, `${port}/tcp`]))
  return {
    ecdsaPort: await readPort(PROFILE_PORTS.ecdsaPort),
    ed25519Port: await readPort(PROFILE_PORTS.ed25519Port),
    forwardingPort: await readPort(PROFILE_PORTS.forwardingPort),
    keyboardInteractivePort: await readPort(PROFILE_PORTS.keyboardInteractivePort),
    maxSessionsPort: await readPort(PROFILE_PORTS.maxSessionsPort),
    passwordPort: await readPort(PROFILE_PORTS.passwordPort),
    primaryPort: await readPort(PRIMARY_SSH_PORT),
    rsaPort: await readPort(PROFILE_PORTS.rsaPort),
    secondaryPort: await readPort(SECONDARY_SSH_PORT),
  }
}

export async function runInIntegrationContainer(
  environment: Pick<IntegrationEnvironment, "containerName">,
  commandArguments: string[]
): Promise<string> {
  return runCommand("docker", ["exec", environment.containerName, ...commandArguments])
}

async function readHostPublicKeys(
  containerName: string
): Promise<IntegrationEnvironment["hostPublicKeys"]> {
  const readKey = async (type: string): Promise<string> =>
    runInIntegrationContainer({ containerName }, ["cat", `/etc/ssh/ssh_host_${type}_key.pub`])
  return {
    ecdsa: await readKey("ecdsa"),
    ed25519: await readKey("ed25519"),
    rsa: await readKey("rsa"),
  }
}

export async function disconnectIntegrationSessions(
  environment: IntegrationEnvironment
): Promise<void> {
  await runInIntegrationContainer(environment, ["pkill", "-f", "^sshd(-session)?: paratix"])
}

export async function waitForIntegrationMarker(
  environment: IntegrationEnvironment,
  marker: string
): Promise<void> {
  await runInIntegrationContainer(environment, [
    "timeout",
    "10",
    "sh",
    "-c",
    'until test -f "$1"; do sleep 0.05; done',
    "sh",
    marker,
  ])
}

export type IntegrationAgent = {
  cleanup: () => Promise<void>
  fingerprint: string
  socket: string
}

function startForegroundAgent(socket: string): {
  assertRunning: () => void
  stop: () => Promise<void>
} {
  const child = spawn("ssh-agent", ["-D", "-a", socket], { stdio: "ignore" })
  let failure: Error | undefined
  child.once("error", (error) => {
    failure = error
  })
  const closed = new Promise<void>((resolve) => {
    child.once("close", () => {
      resolve()
    })
  })
  return {
    assertRunning() {
      if (failure != null) throw failure
      if (child.exitCode !== null || child.signalCode !== null) {
        throw new Error("Test SSH agent exited before becoming ready")
      }
    },
    async stop() {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM")
      const forceKill = setTimeout(() => {
        child.kill("SIGKILL")
      }, SOCKET_TIMEOUT)
      try {
        await closed
      } finally {
        clearTimeout(forceKill)
      }
    },
  }
}

export async function createIntegrationAgent(privateKeyPath: string): Promise<IntegrationAgent> {
  const directory = await mkdtemp(join(tmpdir(), "paratix-integration-agent-"))
  const socket = join(directory, "agent.sock")
  let agentProcess: ReturnType<typeof startForegroundAgent> | undefined
  const cleanup = async (): Promise<void> => {
    try {
      await agentProcess?.stop()
    } finally {
      await rm(directory, { force: true, recursive: true })
    }
  }
  try {
    agentProcess = startForegroundAgent(socket)
    await waitForAgentSocket(socket, agentProcess.assertRunning)
    const env = { ...process.env, SSH_AUTH_SOCK: socket }
    await runCommand("ssh-add", [privateKeyPath], { env })
    const fingerprint = /SHA256:\S+/v.exec(
      await runCommand("ssh-keygen", ["-lf", `${privateKeyPath}.pub`])
    )?.[0]
    if (fingerprint == null) throw new Error("Test key fingerprint is missing")
    return { cleanup, fingerprint, socket }
  } catch (error) {
    await cleanup()
    throw error
  }
}

async function waitForAgentSocket(socket: string, assertRunning: () => void): Promise<void> {
  const deadline = Date.now() + SHORT_COMMAND_TIMEOUT_MS
  while (Date.now() < deadline) {
    assertRunning()
    try {
      // eslint-disable-next-line no-await-in-loop -- readiness belongs to this foreground child.
      await access(socket)
      return
    } catch {
      // The foreground agent creates its socket after spawning.
    }
    // eslint-disable-next-line no-await-in-loop -- wait for this child process, not another agent.
    await sleep(SSH_POLL_INTERVAL)
  }
  throw new Error("Timed out waiting for the test SSH agent socket")
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
    const ports = await readPublishedPorts(containerName)
    await Promise.all(
      Object.values(ports).map(async (port) => waitForTcpPort(HOST, port, SSH_READY_TIMEOUT))
    )
    const password = randomBytes(PASSWORD_RANDOM_BYTES).toString("hex")
    await runCommand("docker", ["exec", "-i", containerName, "chpasswd"], {
      input: `paratix:${password}\n`,
    })
    const hostPublicKeys = await readHostPublicKeys(containerName)
    return {
      cleanup,
      clientPrivateKeyPath,
      containerName,
      dockerImageTag,
      host: HOST,
      hostPublicKey: hostPublicKeys.ed25519,
      hostPublicKeys,
      password,
      ...ports,
      workspaceHome,
    }
  } catch (error) {
    await cleanup()
    throw error
  }
}
