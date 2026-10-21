/* eslint-disable sonarjs/no-nested-template-literals -- Shell fixture commands interpolate quoted resource paths. */
import type { RequestListener } from "node:http"

import { execFileSync } from "node:child_process"
import { readFile } from "node:fs/promises"
import { createServer, type Server } from "node:https"
import { connect } from "node:net"
import { join } from "node:path"
import { Client } from "ssh2"

import type { ExecResult } from "../../src/types.js"

import { shellQuote, type SshConnectionImpl } from "../../src/ssh.js"

const REGISTRY_MAX_HEADER_SIZE = 262_144

const BASIC_AUTH_PREFIX = "Basic "
const HTTP_UNAUTHORIZED = 401
const HTTP_OK = 200
const HTTP_INTERNAL_ERROR = 500

type RegistryState = { hook?: () => Promise<void>; requests: number }
export type NativeRegistry = {
  close: () => Promise<void>
  execute: (command: string, input?: string) => Promise<ExecResult>
  name: string
  requests: () => number
  setHook: (hook?: () => Promise<void>) => void
}

export function requiredPodmanEnvironment(name: string): string {
  const value = process.env[name]
  if (value == null || value.length === 0)
    throw new Error(`Missing ${name} for native Podman integration`)
  return value
}

async function listen(server: Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject)
    server.listen(0, "127.0.0.1", () => {
      const address = server.address()
      if (address === null || typeof address === "string")
        reject(new Error("Missing registry address"))
      else resolve(address.port)
    })
  })
}

async function connectForwarder(): Promise<Client> {
  const client = new Client()
  const privateKey = await readFile(requiredPodmanEnvironment("PARATIX_PODMAN_PRIVATE_KEY"))
  await new Promise<void>((resolve, reject) => {
    client.once("error", reject)
    client.once("ready", resolve)
    client.connect({
      host: requiredPodmanEnvironment("PARATIX_PODMAN_HOST"),
      port: Number(requiredPodmanEnvironment("PARATIX_PODMAN_PORT")),
      privateKey,
      username: requiredPodmanEnvironment("PARATIX_PODMAN_USER"),
    })
  })
  return client
}

async function forwardRegistry(client: Client, localPort: number): Promise<number> {
  client.on("tcp connection", (_details, accept) => {
    const stream = accept()
    const socket = connect(localPort, "127.0.0.1")
    socket.on("error", () => {
      stream.destroy()
    })
    stream.on("error", () => {
      socket.destroy()
    })
    stream.pipe(socket).pipe(stream)
  })
  return new Promise((resolve, reject) => {
    client.forwardIn("127.0.0.1", 0, (error, port) => {
      if (error) reject(error)
      else resolve(port)
    })
  })
}

/**
 * A separate raw channel observes output before Paratix's secret masks.
 * @param client - The dedicated SSH client used for raw stream observation.
 * @param command - The fixture command to execute as effective root.
 * @param input - Optional input forwarded unchanged to the remote process.
 * @returns The unmasked exit code and output streams.
 */
async function rawExecute(client: Client, command: string, input?: string): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    client.exec(`sudo -n -- sh -c ${shellQuote(command)}`, (error, channel) => {
      if (error) {
        reject(error)
        return
      }
      let stdout = ""
      let stderr = ""
      channel.on("data", (chunk: Buffer) => {
        stdout += chunk.toString()
      })
      channel.stderr.on("data", (chunk: Buffer) => {
        stderr += chunk.toString()
      })
      channel.on("error", reject)
      channel.on("close", (code: number) => {
        resolve({ code, stderr, stdout })
      })
      channel.end(input)
    })
  })
}

function handler(username: string, token: string, state: RegistryState): RequestListener {
  const fixtureState = state
  return (request, response): void => {
    const handle = async (): Promise<void> => {
      response.setHeader("Docker-Distribution-Api-Version", "registry/2.0")
      const authorization = request.headers.authorization
      const credentials = authorization?.startsWith(BASIC_AUTH_PREFIX)
        ? Buffer.from(authorization.slice(BASIC_AUTH_PREFIX.length), "base64").toString()
        : ""
      if (
        !credentials.startsWith(`${username}:`) ||
        ![`${token}-rotated`, token].includes(credentials.slice(username.length + 1))
      ) {
        response.writeHead(HTTP_UNAUTHORIZED, {
          "WWW-Authenticate": 'Basic realm="paratix-native-test"',
        })
      } else {
        fixtureState.requests += 1
        const pending = fixtureState.hook
        fixtureState.hook = undefined
        await pending?.()
        response.writeHead(HTTP_OK, { "Content-Type": "application/json" })
      }
      response.end("{}")
    }
    void handle().catch(() => {
      response.writeHead(HTTP_INTERNAL_ERROR)
      response.end()
    })
  }
}

async function certificates(directory: string): Promise<{ cert: Buffer; key: Buffer }> {
  const certificate = join(directory, "ca.crt")
  const key = join(directory, "key.pem")
  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-days",
      "1",
      "-keyout",
      key,
      "-out",
      certificate,
      "-subj",
      "/CN=paratix-test-registry",
      "-addext",
      "subjectAltName=IP:127.0.0.1",
    ],
    { stdio: "ignore" }
  )
  return { cert: await readFile(certificate), key: await readFile(key) }
}

async function closeNetwork(server: Server, client?: Client): Promise<void> {
  server.closeAllConnections()
  if (server.listening)
    await new Promise<void>((resolve) => {
      server.close(() => {
        resolve()
      })
    })
  if (client !== undefined)
    await new Promise<void>((resolve) => {
      client.once("close", resolve)
      client.destroy()
    })
}

// eslint-disable-next-line max-statements -- Resource acquisition and cleanup remain explicit in the fixture constructor.
export async function createNativeRegistry(
  ssh: SshConnectionImpl,
  directory: string,
  credentials: { token: string; username: string }
): Promise<NativeRegistry> {
  const state: RegistryState = { requests: 0 }
  const server = createServer(
    { ...(await certificates(directory)), maxHeaderSize: REGISTRY_MAX_HEADER_SIZE },
    handler(credentials.username, credentials.token, state)
  )
  let client: Client | undefined
  let certificateDirectory: string | undefined
  const close = async (): Promise<void> => {
    try {
      if (certificateDirectory !== undefined)
        await ssh.exec(`rm -rf -- ${shellQuote(certificateDirectory)}`, { silent: true })
    } finally {
      await closeNetwork(server, client)
    }
  }
  try {
    const localPort = await listen(server)
    client = await connectForwarder()
    const name = `127.0.0.1:${String(await forwardRegistry(client, localPort))}`
    const certificatePath = `/etc/containers/certs.d/${name}`
    await ssh.exec("mkdir -p -m 0755 -- /etc/containers/certs.d", { silent: true })
    await ssh.exec(`mkdir -m 0755 -- ${shellQuote(certificatePath)}`, { silent: true })
    certificateDirectory = certificatePath
    await ssh.exec(`cat > ${shellQuote(`${certificatePath}/ca.crt`)}`, {
      input: await readFile(join(directory, "ca.crt"), "utf8"),
      silent: true,
    })
    const forwarder = client
    return {
      close,
      execute: async (command, input) => rawExecute(forwarder, command, input),
      name,
      requests: () => state.requests,
      setHook(hook) {
        state.hook = hook
      },
    }
  } catch (error) {
    await close()
    throw error
  }
}
