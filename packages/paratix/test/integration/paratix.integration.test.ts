import { createHash, randomUUID } from "node:crypto"
import { mkdtempSync, writeFileSync } from "node:fs"
import { readFile, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest"

import type { Environment, Module, SshConfig, SshConnection } from "../../src/types.js"

import { command, download, file, shellQuote } from "../../src/index.js"
import { clearHostKeyCache, HostKeyVerificationError } from "../../src/knownHosts.js"
import { runPlaybook } from "../../src/runner.js"
import { server } from "../../src/server.js"
import { SshConnectionImpl } from "../../src/ssh.js"
import { createIntegrationEnvironment, type IntegrationEnvironment } from "./harness.js"

const emptyEnv = {}
const HTTP_SERVER_READY_DELAY_MS = 250
const HTTP_SERVER_READY_RETRIES = 20
// cspell:ignore ordner konfiguration
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

async function sleep(delayMs: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, delayMs)
  })
}

async function expectModuleCheckOk(
  mod: Module,
  ssh: SshConnection,
  environment: Environment = emptyEnv
): Promise<void> {
  await expect(mod.check(ssh, environment)).resolves.toBe("ok")
}

async function startRemoteHttpServer(
  ssh: SshConnection,
  directory: string,
  port: number
): Promise<void> {
  const pidPath = `/tmp/paratix-http-${String(port)}.pid`
  const logPath = `/tmp/paratix-http-${String(port)}.log`
  // cspell:ignore nohup
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

    await ssh.writeFile(remoteDownloadPath, "download-content\n", { mode: "0644" })
    await ssh.downloadFile(remoteDownloadPath, localDownloadPath)
    expect(await readFile(localDownloadPath, "utf8")).toBe("download-content\n")

    ssh.disconnect()
    await rm(localDirectory, { force: true, recursive: true })
  })

  it("uploads and downloads unicode filenames and content over real SFTP", async () => {
    const environment = getEnvironment()
    const ssh = await connectSsh([environment.primaryPort], {}, "root")
    const localDirectory = mkdtempSync(join(tmpdir(), "paratix-sftp-unicode-"))
    const localUploadPath = join(localDirectory, unicodeFileName)
    const localDownloadPath = join(localDirectory, `download-${unicodeFileName}`)
    const remoteDirectory = "/home/paratix/über ordner"
    const remoteUploadPath = `${remoteDirectory}/${unicodeFileName}`
    const remoteDownloadPath = `${remoteDirectory}/下載-ß.txt`

    writeFileSync(localUploadPath, unicodeContent, "utf8")
    await ssh.exec(`mkdir -p ${shellQuote(remoteDirectory)}`, { silent: true })
    await ssh.uploadFile(localUploadPath, remoteUploadPath)
    expect(await ssh.readFile(remoteUploadPath)).toBe(unicodeContent.trimEnd())

    await ssh.writeFile(remoteDownloadPath, unicodeBlockContent, { mode: "0644" })
    await ssh.downloadFile(remoteDownloadPath, localDownloadPath)
    expect(await readFile(localDownloadPath, "utf8")).toBe(unicodeBlockContent)

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

  it("converges file and command modules to verifiable remote state", async () => {
    const ssh = await connectSsh([getEnvironment().primaryPort], {}, "root")
    const localDirectory = mkdtempSync(join(tmpdir(), "paratix-modules-"))
    const remoteBase = `/root/integration-${randomUUID()}`
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
    const markerPath = `${remoteBase}/app/marker.txt`
    const commandModule = command.shell(`printf '%s\\n' ready > ${shellQuote(markerPath)}`, {
      check: `test -f ${shellQuote(markerPath)}`,
      name: "create integration marker",
    })

    try {
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
    } finally {
      await ssh.exec(`rm -rf ${shellQuote(remoteBase)}`, { silent: true })
      ssh.disconnect()
      await rm(localDirectory, { force: true, recursive: true })
    }
  })

  it("converges unicode file, template, and block modules to verifiable remote state", async () => {
    const ssh = await connectSsh([getEnvironment().primaryPort], {}, "root")
    const localDirectory = mkdtempSync(join(tmpdir(), "paratix-unicode-modules-"))
    const remoteBase = `/root/integration-${randomUUID()}-äöü`
    const remoteDirectory = `${remoteBase}/über ordner`
    const remoteCopyPath = `${remoteDirectory}/${unicodeFileName}`
    const remoteTemplatePath = `${remoteDirectory}/結果-template.txt`
    const remoteBlockPath = `${remoteDirectory}/konfiguration ü.txt`
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

    try {
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
    } finally {
      await ssh.exec(`rm -rf ${shellQuote(remoteBase)}`, { silent: true })
      ssh.disconnect()
      await rm(localDirectory, { force: true, recursive: true })
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
    } finally {
      await stopRemoteHttpServer(ssh, port)
      await ssh.exec(`rm -rf ${shellQuote(remoteBase)}`, { silent: true })
      ssh.disconnect()
    }
  })
})
