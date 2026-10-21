/* eslint-disable sonarjs/no-nested-template-literals -- Shell fixture commands interpolate quoted resource paths. */
import { randomUUID } from "node:crypto"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"

import type { ExecOptions, ExecResult, SshConnection } from "../../src/types.js"
import type { NativeRegistry } from "./podmanRegistry.js"

import { shellQuote, SshConnectionImpl } from "../../src/ssh.js"
import { createNativeRegistry, requiredPodmanEnvironment } from "./podmanRegistry.js"

export const PODMAN_HELPER_IMAGE =
  "docker.io/library/python@sha256:db3231d3fce4c59182f8364dbec08b8bad4fdfca673dfb226f3c9e77b6b48cd2"
const DEFAULT_TOKEN = "paratix-synthetic-token-0089"

export type NativeTrace = { command: string; input: ExecOptions["input"]; result: ExecResult }
export type NativePodmanEnvironment = {
  authenticatedRequests: () => number
  authFile: string
  baseSsh: SshConnectionImpl
  cleanup: () => Promise<void>
  controllerDirectory: string
  helperImage: string
  hostPythonPresent: boolean
  leftovers: () => Promise<string[]>
  passwordFile: string
  rawExecute: (command: string, input?: string) => Promise<ExecResult>
  registry: string
  resource: string
  setRegistryHook: (hook?: () => Promise<void>) => void
  setWrapper: (script: string) => Promise<void>
  ssh: SshConnection
  token: string
  trace: NativeTrace[]
  username: string
  write: (path: string, content: string, mode?: string) => Promise<void>
}
type Target = {
  controllerDirectory: string
  helperImage: string
  resource: string
  ssh: SshConnectionImpl
  token: string
}

export function nativePodmanTargetConfigured(): boolean {
  return process.env.PARATIX_PODMAN_HOST != null
}

function remoteWriter(ssh: SshConnectionImpl): NativePodmanEnvironment["write"] {
  return async (path: string, content: string, mode = "0600"): Promise<void> => {
    await ssh.exec(
      `umask 077; cat > ${shellQuote(path)} && chmod ${shellQuote(mode)} -- ${shellQuote(path)}`,
      { input: content, silent: true }
    )
  }
}

function connection(): SshConnectionImpl {
  return new SshConnectionImpl(requiredPodmanEnvironment("PARATIX_PODMAN_HOST"), {
    expectedHostPublicKey: process.env.PARATIX_PODMAN_HOST_PUBLIC_KEY,
    ports: [Number(requiredPodmanEnvironment("PARATIX_PODMAN_PORT"))],
    privateKey: requiredPodmanEnvironment("PARATIX_PODMAN_PRIVATE_KEY"),
    strictHostKeyChecking: process.env.PARATIX_PODMAN_HOST_PUBLIC_KEY == null ? "no" : "yes",
    user: requiredPodmanEnvironment("PARATIX_PODMAN_USER"),
  })
}

async function preflight(target: Target): Promise<boolean> {
  const { helperImage, resource, ssh } = target
  const versionResult = await ssh.exec("podman version --format '{{.Version}}'", { silent: true })
  const version = versionResult.stdout.trim()
  if (version !== requiredPodmanEnvironment("PARATIX_PODMAN_EXPECTED_VERSION"))
    throw new Error(`Unexpected native Podman version: ${version}`)
  const identity = await ssh.exec("id -u", { silent: true })
  if (identity.stdout.trim() !== "0")
    throw new Error("Native Podman integration requires effective root")
  const python = await ssh.exec("command -v python3", { ignoreExitCode: true, silent: true })
  await ssh.exec(
    `install -d -m 0700 -- ${[resource, `${resource}/auth`, `${resource}/pat`, `${resource}/bin`].map((path) => shellQuote(path)).join(" ")}`,
    { silent: true }
  )
  const result = await ssh.exec(
    `podman run --rm --pull=never --user 0:0 --userns=host --network=none --read-only --read-only-tmpfs=false --cap-drop=all --security-opt=no-new-privileges --log-driver=none --entrypoint python3 ${shellQuote(helperImage)} -I -B -c 'import json; print(json.dumps({"helper":"ready"},separators=(",",":")))'`,
    { ignoreExitCode: true, silent: true }
  )
  if (result.code !== 0 || result.stdout.trim() !== '{"helper":"ready"}')
    throw new Error("Native helper container preflight failed")
  return python.code === 0
}

function instrument(
  target: Target,
  registry: NativeRegistry
): Pick<NativePodmanEnvironment, "leftovers" | "rawExecute" | "ssh" | "trace"> {
  const trace: NativeTrace[] = []
  const containerNames = new Set<string>()
  const observe = (command: string): void => {
    for (const match of command.matchAll(/paratix-auth-[\da-f\-]+-(?:check|prepare|commit)/gv)) {
      containerNames.add(match[0])
    }
  }
  const prefix = `PATH=${shellQuote(`${target.resource}/bin`)}:$PATH `
  const ssh = new Proxy(target.ssh, {
    get(original, property) {
      if (property === "exec")
        return async (command: string, options: ExecOptions = {}) => {
          observe(command)
          const result = await original.exec(`${prefix}${command}`, options)
          trace.push({ command, input: options.input, result })
          return result
        }
      const value: unknown = Reflect.get(original, property)
      // eslint-disable-next-line @typescript-eslint/no-unsafe-return -- Preserve bound SSH methods at the test instrumentation boundary.
      return typeof value === "function" ? value.bind(original) : value
    },
  })
  return {
    async leftovers() {
      const workResult = await target.ssh.exec(
        `find ${shellQuote(target.resource)} -name '.paratix-auth.*' -print`,
        { silent: true }
      )
      const work = workResult.stdout.trim().split("\n").filter(Boolean)
      const containersResult = await target.ssh.exec("podman ps -a --format '{{.Names}}'", {
        silent: true,
      })
      const containers = containersResult.stdout
        .trim()
        .split("\n")
        .filter((name) => containerNames.has(name))
      return [...work, ...containers]
    },
    async rawExecute(command: string, input?: string) {
      observe(command)
      const result = await registry.execute(`${prefix}${command}`, input)
      trace.push({ command, input, result })
      return result
    },
    ssh,
    trace,
  }
}

async function assemble(
  target: Target,
  registry: NativeRegistry,
  lifecycle: { cleanup: () => Promise<void>; hostPythonPresent: boolean }
): Promise<NativePodmanEnvironment> {
  const { controllerDirectory, helperImage, resource, ssh, token } = target
  const { cleanup, hostPythonPresent } = lifecycle
  const write = remoteWriter(ssh)
  const authFile = `${resource}/auth/auth.json`
  const passwordFile = `${resource}/pat/token`
  await write(authFile, "{}")
  await write(passwordFile, token, "0400")
  await write(
    `${resource}/bin/podman`,
    `#!/bin/sh\nprintf '%s\\n' "$1" >> ${shellQuote(`${resource}/calls`)}\nif [ -f ${shellQuote(`${resource}/control`)} ]; then . ${shellQuote(`${resource}/control`)}; fi\nexec /usr/bin/podman "$@"\n`,
    "0700"
  )
  return {
    authenticatedRequests: registry.requests,
    authFile,
    baseSsh: ssh,
    cleanup,
    controllerDirectory,
    helperImage,
    hostPythonPresent,
    passwordFile,
    registry: registry.name,
    resource,
    setRegistryHook: registry.setHook,
    async setWrapper(script) {
      await write(`${resource}/control`, script)
    },
    token,
    username: "u",
    async write(path, content, mode) {
      await write(path, content, mode)
    },
    ...instrument(target, registry),
  }
}

async function dispose(target: Target, registry?: NativeRegistry): Promise<void> {
  try {
    await registry?.close()
    await target.ssh.exec(`rm -rf -- ${shellQuote(target.resource)}`, { silent: true })
  } finally {
    target.ssh.disconnect()
    await rm(target.controllerDirectory, { force: true, recursive: true })
  }
}

export async function createNativePodmanEnvironment(
  options: { token?: string } = {}
): Promise<NativePodmanEnvironment> {
  const resource = `${requiredPodmanEnvironment("PARATIX_PODMAN_TEST_ROOT")}/run-${randomUUID()}`
  if (!/^\/(?:var\/lib|root)\/[\w\/\-]+$/v.test(resource))
    throw new Error("Native Podman test root must be isolated below /var/lib or /root")
  const ssh = connection()
  const target = {
    controllerDirectory: await mkdtemp(join(tmpdir(), "paratix-native-podman-")),
    helperImage: process.env.PARATIX_PODMAN_HELPER_IMAGE ?? PODMAN_HELPER_IMAGE,
    resource,
    ssh,
    token: options.token ?? DEFAULT_TOKEN,
  }
  let registry: NativeRegistry | undefined
  try {
    await ssh.connect()
    const hostPythonPresent = await preflight(target)
    registry = await createNativeRegistry(ssh, target.controllerDirectory, {
      token: target.token,
      username: "u",
    })
    return await assemble(target, registry, {
      async cleanup() {
        await dispose(target, registry)
      },
      hostPythonPresent,
    })
  } catch (error) {
    await dispose(target, registry)
    throw error
  }
}

export async function readNativeAuthFile(environment: NativePodmanEnvironment): Promise<string> {
  const result = await environment.baseSsh.exec(`cat -- ${shellQuote(environment.authFile)}`, {
    silent: true,
  })
  return result.stdout
}
