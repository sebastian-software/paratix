import { execFile } from "node:child_process"
import { randomUUID } from "node:crypto"
import { mkdtemp, readFile, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { SshConnectionImpl } from "../../src/ssh.js"
import { trustCommand } from "./certificateTrustHarness.js"

const BUILD_TIMEOUT_MS = 150_000
const RESOURCE_LABEL = "com.sebastian-software.paratix.integration.managed=true"

export type LoginResult = { code: number; stderr: string; stdout: string }
export type SshdMatchFixture = {
  ca: string
  cleanup: () => Promise<void>
  connectDeploy: () => Promise<SshConnectionImpl>
  container: (args: string[]) => Promise<string>
  login: (command: string) => Promise<LoginResult>
  opsPublicKey: string
  reset: () => Promise<void>
  ssh: SshConnectionImpl
  write: (path: string, content: string, mode?: string) => Promise<void>
}

async function generateKey(path: string): Promise<void> {
  await trustCommand("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", path])
}

async function readPublicKey(path: string): Promise<string> {
  const content = await readFile(path, "utf8")
  return content.trim()
}

async function loginOpsRo(
  options: { identity: string; port: string },
  command: string
): Promise<LoginResult> {
  return new Promise((resolve, reject) => {
    const env = { ...process.env }
    delete env.SSH_AUTH_SOCK
    execFile(
      "ssh",
      [
        "-F",
        "/dev/null",
        // Request a PTY so the proof can observe that the server refuses it.
        "-tt",
        "-p",
        options.port,
        "-i",
        options.identity,
        "-o",
        "IdentityAgent=none",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=5",
        "ops-ro@127.0.0.1",
        command,
      ],
      { env, timeout: 15_000 },
      (error, stdout, stderr) => {
        if (error === null) resolve({ code: 0, stderr, stdout: stdout.replaceAll("\r", "").trim() })
        else if (typeof error.code === "number")
          resolve({ code: error.code, stderr, stdout: stdout.replaceAll("\r", "").trim() })
        else reject(new Error("ops-ro login failed", { cause: error }))
      }
    )
  })
}

async function startContainer(options: {
  containerName: string
  directory: string
  image: string
  packageDirectory: string
}): Promise<string> {
  const { containerName, directory, image, packageDirectory } = options
  await trustCommand(
    "docker",
    [
      "build",
      "--label",
      RESOURCE_LABEL,
      "--build-arg",
      `CLIENT_PUBLIC_KEY=${await readFile(join(directory, "bootstrap.pub"), "utf8")}`,
      "--build-arg",
      `DEPLOY_PUBLIC_KEY=${await readFile(join(directory, "deploy.pub"), "utf8")}`,
      "-t",
      image,
      "-f",
      join(packageDirectory, "test/integration/docker/Dockerfile.sshd-match"),
      packageDirectory,
    ],
    BUILD_TIMEOUT_MS
  )
  await trustCommand("docker", [
    "run",
    "--detach",
    "--name",
    containerName,
    "--label",
    RESOURCE_LABEL,
    "--publish",
    "127.0.0.1::22",
    image,
  ])
  const portOutput = await trustCommand("docker", ["port", containerName, "22/tcp"])
  const port = /:(?<port>\d+)$/v.exec(portOutput)?.groups?.port
  if (port === undefined) throw new Error(`Missing fixture port: ${portOutput}`)
  return port
}

async function connect(
  options: { hostKey: string; port: string },
  identity: { privateKey: string; user: string }
): Promise<SshConnectionImpl> {
  const ssh = new SshConnectionImpl("127.0.0.1", {
    expectedHostPublicKey: options.hostKey,
    ports: [Number(options.port)],
    privateKey: identity.privateKey,
    strictHostKeyChecking: "yes",
    user: identity.user,
  })
  await ssh.connect()
  return ssh
}

async function cleanupSetupFailure(
  error: unknown,
  cleanup: SshdMatchFixture["cleanup"]
): Promise<never> {
  try {
    await cleanup()
  } catch (cleanupError) {
    throw new AggregateError([error, cleanupError], "sshd.match setup and cleanup failed", {
      cause: cleanupError,
    })
  }
  throw error
}

async function startTarget(options: {
  containerName: string
  directory: string
  image: string
  packageDirectory: string
}): Promise<{ hostKey: string; port: string }> {
  for (const name of ["bootstrap", "deploy", "ops-ro", "ca"])
    // eslint-disable-next-line no-await-in-loop -- ssh-keygen runs are cheap and sequential
    await generateKey(join(options.directory, name))
  const port = await startContainer(options)
  const container = async (args: string[]): Promise<string> =>
    trustCommand("docker", ["exec", options.containerName, ...args])
  await container([
    "timeout",
    "10",
    "sh",
    "-c",
    "until test -f /run/main-sshd.pid; do sleep 0.02; done",
  ])
  return { hostKey: await container(["cat", "/etc/ssh/ssh_host_ed25519_key.pub"]), port }
}

const RESET_SCRIPT = [
  "rm -rf /etc/ssh/sshd_config.d/* /etc/ssh/sshd_config.d/.paratix-* /home/ops-ro/.ssh",
  "rm -rf /etc/ssh/auth_principals /etc/ssh/trusted_user_ca_keys /run/fail-reload-once",
  "cp /run/initial-sshd-config /etc/ssh/sshd_config",
  "systemctl reload ssh",
  "rm -f /run/confirmed-reloads",
].join("; ")

export async function createSshdMatchFixture(packageDirectory: string): Promise<SshdMatchFixture> {
  const directory = await mkdtemp(join(tmpdir(), "paratix-sshd-match-"))
  const id = randomUUID()
  const containerName = `paratix-sshd-match-${id}`
  const image = `paratix-sshd-match:${id}`
  const container = async (args: string[]): Promise<string> =>
    trustCommand("docker", ["exec", containerName, ...args])
  const connections: SshConnectionImpl[] = []
  const cleanup = async (): Promise<void> => {
    for (const connection of connections) connection.disconnect()
    // Each operation is scoped to this fixture's UUID, including failed setup.
    const results = await Promise.allSettled([trustCommand("docker", ["rm", "-f", containerName])])
    const imageRemoval = await Promise.allSettled([
      trustCommand("docker", ["image", "rm", "-f", image]),
    ])
    await rm(directory, { force: true, recursive: true })
    const failures = [...results, ...imageRemoval].filter((result) => result.status === "rejected")
    if (failures.length > 0)
      throw new Error(`sshd.match cleanup failed: ${JSON.stringify(failures)}`)
  }
  try {
    const target = await startTarget({ containerName, directory, image, packageDirectory })
    const ssh = await connect(target, { privateKey: join(directory, "bootstrap"), user: "root" })
    connections.push(ssh)
    return {
      ca: await readFile(join(directory, "ca.pub"), "utf8"),
      cleanup,
      async connectDeploy() {
        const deploy = await connect(target, {
          privateKey: join(directory, "deploy"),
          user: "deploy",
        })
        connections.push(deploy)
        return deploy
      },
      container,
      login: async (command) =>
        loginOpsRo({ identity: join(directory, "ops-ro"), port: target.port }, command),
      opsPublicKey: await readPublicKey(join(directory, "ops-ro.pub")),
      async reset() {
        await container(["sh", "-c", RESET_SCRIPT])
      },
      ssh,
      async write(path, content, mode = "0644") {
        await container([
          "sh",
          "-c",
          'printf "%s" "$1" > "$2" && chmod "$3" "$2"',
          "fixture",
          content,
          path,
          mode,
        ])
      },
    }
  } catch (error) {
    return cleanupSetupFailure(error, cleanup)
  }
}
