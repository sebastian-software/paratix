import { mkdtempSync, writeFileSync } from "node:fs"
import { readFile, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest"

import type { SshConfig } from "../../src/types.js"

import { command, file, shellQuote } from "../../src/index.js"
import { clearHostKeyCache, HostKeyVerificationError } from "../../src/knownHosts.js"
import { runPlaybook } from "../../src/runner.js"
import { server } from "../../src/server.js"
import { SshConnectionImpl } from "../../src/ssh.js"
import { createIntegrationEnvironment, type IntegrationEnvironment } from "./harness.js"

let integrationEnvironment: IntegrationEnvironment | undefined
let originalHome: string | undefined
let testHome: string

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

describe("Paratix integration", () => {
  beforeAll(async () => {
    integrationEnvironment = await createIntegrationEnvironment(
      resolve(import.meta.dirname, "../..")
    )
    originalHome = process.env.HOME
  })

  afterAll(async () => {
    process.env.HOME = originalHome
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

    await expect(ssh.connect()).rejects.toBeInstanceOf(HostKeyVerificationError)
  })

  it("connects with a pinned host key and passes probeSudo against the real server", async () => {
    const environment = getEnvironment()
    const ssh = await connectSsh([environment.primaryPort])
    await expect(ssh.probeSudo()).resolves.toBeUndefined()
    expect(ssh.getConnectionInfo().port).toBe(environment.primaryPort)
    ssh.disconnect()
  })

  it("uploads and downloads files over real SFTP", async () => {
    const environment = getEnvironment()
    const ssh = await connectSsh([environment.primaryPort], {}, "root")
    const localDirectory = mkdtempSync(join(tmpdir(), "paratix-sftp-"))
    const localUploadPath = join(localDirectory, "upload.txt")
    const localDownloadPath = join(localDirectory, "download.txt")
    const remoteUploadPath = "/home/paratix/uploaded.txt"
    const remoteDownloadPath = "/home/paratix/remote.txt"

    writeFileSync(localUploadPath, "upload-content\n", "utf8")
    await ssh.uploadFile(localUploadPath, remoteUploadPath)
    expect(await ssh.readFile(remoteUploadPath)).toBe("upload-content")

    await ssh.writeFile(remoteDownloadPath, "download-content\n")
    await ssh.downloadFile(remoteDownloadPath, localDownloadPath)
    expect(await readFile(localDownloadPath, "utf8")).toBe("download-content\n")

    ssh.disconnect()
    await rm(localDirectory, { force: true, recursive: true })
  })

  it("reconnects successfully on a different configured port", async () => {
    const environment = getEnvironment()
    const ssh = await connectSsh([environment.primaryPort])

    ssh.removePort(environment.primaryPort)
    ssh.addPort(environment.secondaryPort)
    await ssh.reconnect()

    expect(ssh.getConnectionInfo().port).toBe(environment.secondaryPort)
    expect(await ssh.output("whoami")).toBe("root")
    ssh.disconnect()
  })

  it("runs a real happy-path playbook against the integration server", async () => {
    const environment = getEnvironment()
    const localDirectory = mkdtempSync(join(tmpdir(), "paratix-playbook-"))
    const localSourcePath = join(localDirectory, "source.txt")
    const localTemplatePath = join(localDirectory, "template.tmpl")

    writeFileSync(localSourcePath, "copied-from-local\n", "utf8")
    writeFileSync(localTemplatePath, "Hello {{NAME|raw}}\n", "utf8")

    const definition = server({
      env: { NAME: "integration" },
      host: environment.host,
      name: "integration-happy-path",
      run: [
        file.directory("/root/app"),
        file.copy("/root/app/source.txt", localSourcePath),
        file.template("/root/app/template.txt", localTemplatePath),
        command.shell(`printf '%s\\n' ready > ${shellQuote("/root/app/marker.txt")}`, {
          check: `test -f ${shellQuote("/root/app/marker.txt")}`,
          name: "create marker",
        }),
      ],
      ssh: createSshConfig([environment.primaryPort], {}, "root"),
    })

    await expect(runPlaybook(definition)).resolves.toBeUndefined()
    expect(process.exitCode).toBe(0)

    const ssh = await connectSsh([environment.primaryPort], {}, "root")
    expect(await ssh.readFile("/root/app/source.txt")).toBe("copied-from-local")
    expect(await ssh.readFile("/root/app/template.txt")).toBe("Hello integration")
    expect(await ssh.readFile("/root/app/marker.txt")).toBe("ready")
    ssh.disconnect()

    await rm(localDirectory, { force: true, recursive: true })
  })
})
