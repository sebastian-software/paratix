import { spawnSync } from "node:child_process"
import { access, writeFile } from "node:fs/promises"
import { join, resolve } from "node:path"
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest"

import type { SshConfig } from "../../src/types.js"

import { rsync } from "../../src/modules/rsync.js"
import { SshConnectionImpl } from "../../src/ssh.js"
import {
  type CertificateEnvironment,
  createCertificateEnvironment,
  listAgentIdentities,
} from "./certificateHarness.js"
import {
  createIntegrationAgent,
  type IntegrationAgent,
  restoreHomeEnvironmentVariable,
  runInIntegrationContainer,
} from "./harness.js"

const dockerAvailable =
  spawnSync("docker", ["info"], { stdio: "ignore", timeout: 30_000 }).status === 0
if (!dockerAvailable && process.env.CI === "true") {
  throw new Error("Certificate integration proofs require a reachable Docker daemon in CI")
}

let environment: CertificateEnvironment | undefined
let agent: IntegrationAgent | undefined
let connection: SshConnectionImpl | undefined
let originalHome: string | undefined
let originalAgentSocket: string | undefined

function fixture(): CertificateEnvironment {
  if (environment == null) throw new Error("Certificate fixture has not been initialized")
  return environment
}

function createConnection(overrides: Partial<SshConfig> = {}): SshConnectionImpl {
  const target = fixture()
  connection = new SshConnectionImpl(target.host, {
    certificate: "~/external certificates/deployment certificate.pub",
    expectedHostPublicKey: target.hostPublicKey,
    ports: [target.certificatePort],
    privateKey: "~/.ssh/file_rsa",
    strictHostKeyChecking: "yes",
    user: "paratix",
    ...overrides,
  })
  return connection
}

function restoreAgentSocket(): void {
  if (originalAgentSocket === undefined) delete process.env.SSH_AUTH_SOCK
  else process.env.SSH_AUTH_SOCK = originalAgentSocket
}

function useFixtureHome(workspaceHome: string): void {
  process.env.HOME = workspaceHome
}

function testAgent(): IntegrationAgent {
  if (agent == null) throw new Error("Test SSH agent has not been initialized")
  return agent
}

describe.skipIf(!dockerAvailable)("OpenSSH user certificates", { concurrent: false }, () => {
  beforeAll(async () => {
    originalHome = process.env.HOME
    originalAgentSocket = process.env.SSH_AUTH_SOCK
    delete process.env.SSH_AUTH_SOCK
    environment = await createCertificateEnvironment(resolve(import.meta.dirname, "../.."))
    useFixtureHome(environment.workspaceHome)
    agent = await createIntegrationAgent(environment.clientPrivateKeyPath)
  })

  beforeEach(() => {
    delete process.env.SSH_AUTH_SOCK
  })

  afterEach(() => {
    connection?.disconnect()
    connection = undefined
    process.exitCode = 0
  })

  afterAll(async () => {
    restoreHomeEnvironmentVariable(originalHome)
    restoreAgentSocket()
    try {
      await agent?.cleanup()
    } finally {
      await environment?.cleanup()
    }
  })

  it("logs in with an RSA file certificate and a server-authorized principal different from the user", async () => {
    const target = fixture()
    const policy = await runInIntegrationContainer(target, [
      "/usr/sbin/sshd",
      "-T",
      "-f",
      "/etc/ssh/sshd_config.certificate",
    ])
    expect(policy).toContain("authorizedkeysfile none")
    expect(policy).toContain("authorizedprincipalsfile /etc/ssh/test-authorized-principals")
    expect(policy).toContain("trustedusercakeys /etc/ssh/test-user-ca.pub")
    expect(policy).not.toMatch(/pubkeyacceptedalgorithms .*[, ]ssh-rsa-cert-v01@openssh.com[,\n]/v)
    const ssh = createConnection()
    await ssh.connect()
    const result = await ssh.exec("printf certificate-file-ok")
    expect(result.stdout).toBe("certificate-file-ok")
    expect(ssh.getConnectionInfo()).toMatchObject({
      authMethod: "privateKey",
      certificatePath: target.certificatePath,
      privateKeyPath: target.filePrivateKeyPath,
      verifiedHostPublicKey: target.hostPublicKey.split(/\s+/v).slice(0, 2).join(" "),
    })
    expect(ssh.getConnectionInfo().agentSocket).toBeUndefined()
  })

  it("rejects the same bare RSA key on the CA-only server", async () => {
    const ssh = createConnection({ certificate: undefined })
    await expect(ssh.connect()).rejects.toThrow("authentication failed [AUTH_FAILED]")
    expect(ssh.getConnectionInfo().certificatePath).toBeUndefined()
  })

  it("uses an existing certificate identity from the isolated test agent without file metadata", async () => {
    const selectedAgent = testAgent()
    expect(await listAgentIdentities(selectedAgent.socket)).toContain(
      "ssh-ed25519-cert-v01@openssh.com"
    )
    process.env.SSH_AUTH_SOCK = selectedAgent.socket
    const ssh = createConnection({ certificate: undefined, privateKey: undefined })
    await ssh.connect()
    const result = await ssh.exec("printf certificate-agent-ok")
    expect(result.stdout).toBe("certificate-agent-ok")
    expect(ssh.getConnectionInfo()).toMatchObject({
      agentSocket: selectedAgent.socket,
      authMethod: "agent",
    })
    expect(ssh.getConnectionInfo().certificatePath).toBeUndefined()
    expect(ssh.getConnectionInfo().privateKeyPath).toBeUndefined()
  })

  it("transfers real rsync data using an external certificate path with spaces and the verified host anchor", async () => {
    const target = fixture()
    await expect(access(`${target.filePrivateKeyPath}-cert.pub`)).rejects.toThrow(/ENOENT/v)
    expect(target.certificatePath).toContain("external certificates/deployment certificate.pub")
    const source = join(target.workspaceHome, "rsync-source.txt")
    const destination = "/tmp/paratix-certificate-rsync.txt"
    const content = "transferred through the external user certificate\n"
    await writeFile(source, content)
    const ssh = createConnection()
    await ssh.connect()
    expect(ssh.getConnectionInfo().certificatePath).toBe(target.certificatePath)
    expect(ssh.getConnectionInfo().verifiedHostPublicKey).toBe(
      target.hostPublicKey.split(/\s+/v).slice(0, 2).join(" ")
    )
    const module = rsync.sync({ dest: destination, src: source })
    const result = await module.apply(ssh, {})
    expect(result.error?.message).toBeUndefined()
    expect(result.status).toBe("changed")
    await expect(ssh.readFile(destination)).resolves.toBe(content)
    await expect(module.check(ssh, {})).resolves.toBe("ok")
  })
})
