import { execFile } from "node:child_process"
import { randomUUID } from "node:crypto"
import { mkdtemp, readFile, rename, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { SshConnectionImpl } from "../../src/ssh.js"

const COMMAND_MAX_BUFFER = 4_194_304
const BUILD_TIMEOUT_MS = 150_000
const SSH_KEYGEN = "ssh-keygen"
const PRINCIPAL = "release-team"
const RESOURCE_LABEL = "com.sebastian-software.paratix.integration.managed=true"

export type TrustIdentity = { certificate: string; privateKey: string }
export type TrustFixture = {
  ca1: string
  ca2: string
  cleanup: () => Promise<void>
  container: (args: string[]) => Promise<string>
  directory: string
  identities: Record<"first" | "revoked" | "second" | "untrusted" | "wrong", TrustIdentity>
  krl: string
  probe: (
    identity: TrustIdentity,
    bare?: boolean
  ) => Promise<{ code: number; stderr: string; stdout: string }>
  reset: () => Promise<void>
  ssh: SshConnectionImpl
  write: (path: string, content: string, mode?: string) => Promise<void>
}

export async function trustCommand(
  command: string,
  args: string[],
  timeout = 30_000
): Promise<string> {
  return new Promise((resolve, reject) => {
    // The fixture never consults the user's SSH agent, config or credentials.
    const env = { ...process.env }
    delete env.SSH_AUTH_SOCK
    execFile(
      command,
      args,
      { env, maxBuffer: COMMAND_MAX_BUFFER, timeout },
      (error, stdout, stderr) => {
        if (error === null) resolve(stdout.trim())
        else reject(new Error(`${command} failed: ${stderr}\n${stdout}`, { cause: error }))
      }
    )
  })
}

async function generateKey(path: string): Promise<void> {
  await trustCommand(SSH_KEYGEN, ["-q", "-t", "ed25519", "-N", "", "-f", path])
}

async function generateIdentity(
  directory: string,
  name: string,
  options: { ca: string; principal: string }
): Promise<TrustIdentity> {
  const privateKey = join(directory, name)
  await generateKey(privateKey)
  await trustCommand(SSH_KEYGEN, [
    "-q",
    "-s",
    options.ca,
    "-I",
    name,
    "-n",
    options.principal,
    "-V",
    "-5m:+1h",
    `${privateKey}.pub`,
  ])
  const certificate = join(directory, `${name}.certificate`)
  await rename(`${privateKey}-cert.pub`, certificate)
  return { certificate, privateKey }
}

async function probeIdentity(
  port: string,
  identity: TrustIdentity,
  bare: boolean
): ReturnType<TrustFixture["probe"]> {
  return new Promise((resolve, reject) => {
    const env = { ...process.env }
    delete env.SSH_AUTH_SOCK
    execFile(
      "ssh",
      [
        "-F",
        "/dev/null",
        "-p",
        port,
        "-i",
        identity.privateKey,
        "-o",
        `CertificateFile=${bare ? "none" : identity.certificate}`,
        "-o",
        "IdentityAgent=none",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
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
        "deploy@127.0.0.1",
        "id -un",
      ],
      { env, timeout: 15_000 },
      (error, stdout, stderr) => {
        if (error === null) resolve({ code: 0, stderr, stdout: stdout.trim() })
        else if (typeof error.code === "number")
          resolve({ code: error.code, stderr, stdout: stdout.trim() })
        else reject(new Error("SSH probe failed", { cause: error }))
      }
    )
  })
}

type TrustAssets = { bootstrap: string } & Pick<TrustFixture, "ca1" | "ca2" | "identities" | "krl">

async function generateTrustAssets(directory: string): Promise<TrustAssets> {
  const bootstrap = join(directory, "bootstrap")
  const ca1Path = join(directory, "ca1")
  const ca2Path = join(directory, "ca2")
  const unknownCa = join(directory, "unknown-ca")
  await generateKey(bootstrap)
  await generateKey(ca1Path)
  await generateKey(ca2Path)
  await generateKey(unknownCa)
  const identities = {
    first: await generateIdentity(directory, "first", { ca: ca1Path, principal: PRINCIPAL }),
    revoked: await generateIdentity(directory, "revoked", { ca: ca1Path, principal: PRINCIPAL }),
    second: await generateIdentity(directory, "second", { ca: ca2Path, principal: PRINCIPAL }),
    untrusted: await generateIdentity(directory, "untrusted", {
      ca: unknownCa,
      principal: PRINCIPAL,
    }),
    wrong: await generateIdentity(directory, "wrong", { ca: ca1Path, principal: "other-team" }),
  }
  const krl = join(directory, "revoked.krl")
  await trustCommand(SSH_KEYGEN, ["-q", "-k", "-f", krl, identities.revoked.certificate])

  return {
    bootstrap,
    ca1: await readFile(`${ca1Path}.pub`, "utf8"),
    ca2: await readFile(`${ca2Path}.pub`, "utf8"),
    identities,
    krl,
  }
}

async function startTrustContainer(options: {
  bootstrap: string
  containerName: string
  image: string
  packageDirectory: string
}): Promise<string> {
  const { bootstrap, containerName, image, packageDirectory } = options
  const bootstrapPublicKey = await readFile(`${bootstrap}.pub`, "utf8")
  await trustCommand(
    "docker",
    [
      "build",
      "--label",
      RESOURCE_LABEL,
      "--build-arg",
      `CLIENT_PUBLIC_KEY=${bootstrapPublicKey}`,
      "-t",
      image,
      "-f",
      join(packageDirectory, "test/integration/docker/Dockerfile.certificate-trust"),
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

async function connectTrustBootstrap(
  container: TrustFixture["container"],
  port: string,
  bootstrap: string
): Promise<SshConnectionImpl> {
  await container([
    "timeout",
    "10",
    "sh",
    "-c",
    "until test -f /run/main-sshd.pid; do sleep 0.02; done",
  ])
  const ssh = new SshConnectionImpl("127.0.0.1", {
    expectedHostPublicKey: await container(["cat", "/etc/ssh/ssh_host_ed25519_key.pub"]),
    ports: [Number(port)],
    privateKey: bootstrap,
    strictHostKeyChecking: "yes",
    user: "root",
  })
  await ssh.connect()
  return ssh
}

async function cleanupSetupFailure(
  error: unknown,
  cleanup: TrustFixture["cleanup"]
): Promise<never> {
  try {
    await cleanup()
  } catch (cleanupError) {
    throw new AggregateError([error, cleanupError], "Certificate trust setup and cleanup failed", {
      cause: cleanupError,
    })
  }
  throw error
}

export async function createTrustFixture(packageDirectory: string): Promise<TrustFixture> {
  const directory = await mkdtemp(join(tmpdir(), "paratix-certificate-trust-"))
  const id = randomUUID()
  const containerName = `paratix-certificate-trust-${id}`
  const image = `paratix-certificate-trust:${id}`
  const container = async (args: string[]): Promise<string> =>
    trustCommand("docker", ["exec", containerName, ...args])
  let ssh: SshConnectionImpl | undefined
  const cleanup = async (): Promise<void> => {
    ssh?.disconnect()
    // Each operation is scoped to this fixture's UUID, including failed setup.
    const results = await Promise.allSettled([trustCommand("docker", ["rm", "-f", containerName])])
    const imageRemoval = await Promise.allSettled([
      trustCommand("docker", ["image", "rm", "-f", image]),
    ])
    await rm(directory, { force: true, recursive: true })
    const failures = [...results, ...imageRemoval].filter((result) => result.status === "rejected")
    if (failures.length > 0)
      throw new Error(`Certificate trust cleanup failed: ${JSON.stringify(failures)}`)
  }
  try {
    const assets = await generateTrustAssets(directory)
    const port = await startTrustContainer({
      bootstrap: assets.bootstrap,
      containerName,
      image,
      packageDirectory,
    })
    ssh = await connectTrustBootstrap(container, port, assets.bootstrap)
    const write: TrustFixture["write"] = async (path, content, mode = "0644") => {
      await container([
        "sh",
        "-c",
        'printf "%s" "$1" > "$2" && chmod "$3" "$2"',
        "fixture",
        content,
        path,
        mode,
      ])
    }
    return {
      ca1: assets.ca1,
      ca2: assets.ca2,
      cleanup,
      container,
      directory,
      identities: assets.identities,
      krl: assets.krl,
      probe: async (identity, bare = false) => probeIdentity(port, identity, bare),
      async reset() {
        await container([
          "sh",
          "-c",
          "rm -rf /etc/ssh/auth_principals /etc/ssh/custom /etc/ssh/conf.d /etc/ssh/trusted_user_ca_keys /etc/ssh/revoked_keys /run/fail-reload-once /run/fail-all-reloads; cp /run/initial-sshd-config /etc/ssh/sshd_config; systemctl reload ssh; rm -f /run/confirmed-reloads",
        ])
      },
      ssh,
      write,
    }
  } catch (error) {
    return cleanupSetupFailure(error, cleanup)
  }
}
