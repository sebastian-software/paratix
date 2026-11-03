import { spawnSync } from "node:child_process"
import { access, appendFile, chmod, mkdir, readFile, unlink, writeFile } from "node:fs/promises"
import { join, resolve } from "node:path"
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest"

import { waitForKnownHostsWrites } from "../../src/knownHosts.js"
import { rsync } from "../../src/modules/rsync.js"
import { loadNativeBinding } from "../../src/nativeBinding.js"
import { SshConnectionImpl } from "../../src/ssh.js"
import { CommandError, shellQuote } from "../../src/sshHelpers.js"
import {
  createIntegrationEnvironment,
  type IntegrationEnvironment,
  restoreHomeEnvironmentVariable,
  runInIntegrationContainer,
} from "./harness.js"

const dockerAvailable =
  spawnSync("docker", ["info"], { stdio: "ignore", timeout: 30_000 }).status === 0
if (!dockerAvailable && process.env.CI === "true")
  throw new Error("Host certificates require Docker in CI")
let environment: IntegrationEnvironment | undefined
let originalHome: string | undefined
let originalPath: string | undefined
let authority = ""
let connection: SshConnectionImpl | undefined
function fixturePath(bin: string): string {
  return `${bin}:${originalPath ?? ""}`
}
function useFixtureHome(home: string): void {
  process.env.HOME = home
}
function fixture(): IntegrationEnvironment {
  if (environment == null) throw new Error("Missing host certificate fixture")
  return environment
}
async function remote(args: string[]): Promise<string> {
  return runInIntegrationContainer(fixture(), args)
}
async function publicKey(path: string): Promise<string> {
  const content = await remote(["cat", path])
  return content.trim().split(/\s+/v).slice(0, 2).join(" ")
}
async function hostPublicKey(parameters: CertificateParameters = {}): Promise<string> {
  return publicKey(
    `/etc/ssh/ssh_host_${parameters.algorithm ?? "ed25519"}${parameters.bits ?? ""}_key.pub`
  )
}
async function knownHosts(extra = "", ca = authority): Promise<void> {
  const target = fixture()
  await writeFile(
    join(target.workspaceHome, ".ssh", "known_hosts"),
    `@cert-authority [${target.host}]:${target.ed25519Port} ${ca}\n${extra}`
  )
}
type CertificateParameters = {
  algorithm?: "ecdsa" | "ed25519" | "rsa"
  bits?: number
  ca?: string
  certOnly?: boolean
  critical?: boolean
  emptyPrincipals?: boolean
  invalidSignature?: boolean
  principal?: string
  rawOnly?: boolean
  rotate?: boolean
  userCertificate?: boolean
  validity?: string
}
async function issueCertificate(parameters: CertificateParameters, key: string): Promise<void> {
  await remote([
    "ssh-keygen",
    "-q",
    "-s",
    parameters.ca ?? "/etc/ssh/host_ca",
    "-I",
    "isolated-host-fixture",
    ...(parameters.userCertificate ? [] : ["-h"]),
    ...(parameters.emptyPrincipals ? [] : ["-n", parameters.principal ?? fixture().host]),
    ...(parameters.critical ? ["-O", "critical:fixture=denied"] : []),
    "-V",
    parameters.validity ?? "-5m:+1d",
    `${key}.pub`,
  ])
  if (!parameters.invalidSignature) return
  const content = await remote(["cat", `${key}-cert.pub`])
  const fields = content.split(/\s+/v)
  const blob = Buffer.from(fields[1] ?? "", "base64")
  blob[blob.length - 1] = (blob.at(-1) ?? 0) ^ 1
  await remote([
    "sh",
    "-c",
    'printf "%s\\n" "$1" > "$2"',
    "fixture",
    `${fields[0]} ${blob.toString("base64")}`,
    `${key}-cert.pub`,
  ])
}
async function prepareHostKey(parameters: CertificateParameters): Promise<string> {
  const algorithm = parameters.algorithm ?? "ed25519"
  const key = `/etc/ssh/ssh_host_${algorithm}${parameters.bits ?? ""}_key`
  if (parameters.rotate || parameters.bits != null) {
    const bits = parameters.bits == null ? "" : `-b ${parameters.bits}`
    await remote([
      "sh",
      "-c",
      `rm -f ${key} ${key}.pub ${key}-cert.pub; ssh-keygen -q -t ${algorithm} ${bits} -N '' -f ${key}`,
    ])
  }
  await issueCertificate(parameters, key)
  return key
}
async function configure(parameters: CertificateParameters = {}): Promise<void> {
  const algorithm = parameters.algorithm ?? "ed25519"
  const key = await prepareHostKey(parameters)
  const rawAlgorithms = {
    ecdsa: `ecdsa-sha2-nistp${parameters.bits ?? 256}`,
    ed25519: "ssh-ed25519",
    rsa: "rsa-sha2-512,rsa-sha2-256",
  }[algorithm]
  const certAlgorithms =
    algorithm === "rsa"
      ? "rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com"
      : `${rawAlgorithms}-cert-v01@openssh.com`
  const certificateLine = parameters.rawOnly ? "" : `HostCertificate ${key}-cert.pub\n`
  let algorithms = `${certAlgorithms},${rawAlgorithms}`
  if (parameters.rawOnly) algorithms = rawAlgorithms
  else if (parameters.certOnly) algorithms = certAlgorithms
  const config = `Port 2226\nPidFile /run/sshd-ed25519.pid\nHostKey ${key}\n${certificateLine}HostKeyAlgorithms ${algorithms}\nListenAddress 0.0.0.0\nAuthorizedKeysFile .ssh/authorized_keys\nAllowUsers paratix\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nSubsystem sftp internal-sftp\n`
  await remote([
    "sh",
    "-c",
    `printf "%s" "$1" > /etc/ssh/sshd_config.ed25519; /usr/sbin/sshd -t -f /etc/ssh/sshd_config.ed25519; kill -HUP "$(cat /run/sshd-ed25519.pid)"; for i in $(seq 1 100); do ssh-keyscan ${parameters.certOnly ? "-c " : ""}-T 1 -p 2226 127.0.0.1 >/dev/null 2>&1 && exit 0; sleep 0.05; done; exit 1`,
    "fixture",
    config,
  ])
}
async function connect(
  pin?: string,
  mode: "accept-new" | "yes" = "yes",
  privateKey?: string
): Promise<SshConnectionImpl> {
  const target = fixture()
  connection = new SshConnectionImpl(target.host, {
    expectedHostPublicKey: pin,
    ports: [target.ed25519Port],
    privateKey: privateKey ?? target.clientPrivateKeyPath,
    strictHostKeyChecking: mode,
    user: "paratix",
  })
  await connection.connect()
  return connection
}
async function transfer(ssh: SshConnectionImpl): Promise<string | undefined> {
  const target = fixture()
  const source = join(target.workspaceHome, "host-cert-source.txt")
  await writeFile(source, "host certificate transfer\n")
  const result = await rsync
    .sync({ dest: "/tmp/host-cert-transfer.txt", src: source })
    .apply(ssh, {})
  return result.error instanceof CommandError
    ? `${result.error.message}\n${result.error.fullStderr}`
    : result.error?.message
}

describe.skipIf(!dockerAvailable)(
  "controller host certificates and real rsync",
  { concurrent: false },
  () => {
    beforeAll(async () => {
      originalHome = process.env.HOME
      originalPath = process.env.PATH
      environment = await createIntegrationEnvironment(resolve(import.meta.dirname, "../.."))
      useFixtureHome(environment.workspaceHome)
      await remote([
        "ssh-keygen",
        "-q",
        "-t",
        "rsa",
        "-b",
        "2048",
        "-N",
        "",
        "-f",
        "/etc/ssh/host_ca",
      ])
      await remote(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", "/etc/ssh/foreign_ca"])
      authority = await publicKey("/etc/ssh/host_ca.pub")
    })
    afterEach(() => {
      process.env.PATH = originalPath
      connection?.disconnect()
      connection = undefined
      process.exitCode = 0
    })
    afterAll(async () => {
      restoreHomeEnvironmentVariable(originalHome)
      await environment?.cleanup()
    })

    it.each([
      { algorithm: "ed25519" },
      { algorithm: "ecdsa" },
      { algorithm: "ecdsa", bits: 384 },
      { algorithm: "ecdsa", bits: 521 },
      { algorithm: "rsa" },
    ] as const)(
      "connects and transfers using only the CA for a $algorithm/$bits leaf",
      async (parameters) => {
        await configure(parameters)
        await knownHosts()
        const ssh = await connect()
        const expected = await hostPublicKey(parameters)
        expect(ssh.getConnectionInfo().verifiedHostPublicKey).toBe(expected)
        expect(ssh.getConnectionInfo().hostVerificationEvidence).toMatchObject({
          authorityPublicKey: authority,
          explicitPins: false,
          kind: "certificate",
        })
        expect(await transfer(ssh)).toBeUndefined()
      }
    )

    it("persists a raw-only server with a CA only after successful authentication", async () => {
      await configure({ rawOnly: true })
      await knownHosts()
      const path = join(fixture().workspaceHome, ".ssh", "known_hosts")
      const before = await readFile(path, "utf8")
      const wrongKey = join(fixture().workspaceHome, "unauthorized-key")
      const generated = spawnSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", wrongKey], {
        timeout: 10_000,
      })
      expect(generated.status).toBe(0)
      await expect(connect(undefined, "accept-new", wrongKey)).rejects.toThrow(
        /authentication failed/iv
      )
      await waitForKnownHostsWrites()
      expect(await readFile(path, "utf8")).toBe(before)
      connection?.disconnect()
      const ssh = await connect(undefined, "accept-new")
      await waitForKnownHostsWrites()
      const leaf = ssh.getConnectionInfo().verifiedHostPublicKey
      expect(ssh.getConnectionInfo().hostVerificationEvidence).toMatchObject({
        kind: "key",
        publicKey: leaf,
      })
      expect(await readFile(path, "utf8")).toBe(
        `${before}[${fixture().host}]:${fixture().ed25519Port} ${leaf}\n`
      )
      ssh.disconnect()
      await connect()
    })

    it("replaces real reconnect CA evidence for the same leaf and preserves it after rejection", async () => {
      await configure()
      await knownHosts()
      const ssh = await connect()
      const initial = ssh.getConnectionInfo()
      const replacement = await publicKey("/etc/ssh/foreign_ca.pub")
      await configure({ ca: "/etc/ssh/foreign_ca" })
      await knownHosts("", replacement)
      await ssh.reconnect({ defaultTimeout: 5000 })
      const accepted = ssh.getConnectionInfo()
      expect(accepted.verifiedHostPublicKey).toBe(initial.verifiedHostPublicKey)
      expect(accepted.hostVerificationEvidence).toStrictEqual({
        ...initial.hostVerificationEvidence,
        authorityPublicKey: replacement,
      })
      expect(accepted.hostVerificationEvidence).not.toStrictEqual(initial.hostVerificationEvidence)
      await configure()
      await expect(ssh.reconnect({ defaultTimeout: 5000 })).rejects.toThrow(
        /HOST KEY VERIFICATION FAILED/v
      )
      expect(ssh.getConnectionInfo().verifiedHostPublicKey).toBe(accepted.verifiedHostPublicKey)
      expect(ssh.getConnectionInfo().hostVerificationEvidence).toStrictEqual(
        accepted.hostVerificationEvidence
      )
    })

    it.each([
      { expected: { kind: "certificate" }, label: "valid", parameters: {} },
      {
        expected: {
          error: expect.objectContaining({
            message: expect.stringMatching(/HOST KEY VERIFICATION FAILED/v),
          }),
        },
        label: "invalid",
        parameters: { principal: "foreign.example" },
      },
    ])(
      "never persists a $label certificate to unwritable known_hosts in accept-new mode",
      async ({ expected, parameters }) => {
        await configure(parameters)
        await knownHosts()
        const path = join(fixture().workspaceHome, ".ssh", "known_hosts")
        const before = await readFile(path, "utf8")
        await chmod(path, 0o400)
        try {
          // Negative control: this actual file cannot accept the raw TOFU append.
          await expect(appendFile(path, "unwanted\n")).rejects.toThrow(/EACCES|EPERM/v)
          let outcome: unknown
          try {
            const ssh = await connect(undefined, "accept-new")
            outcome = { kind: ssh.getConnectionInfo().hostVerificationEvidence?.kind }
          } catch (error) {
            outcome = { error }
          }
          expect(outcome).toStrictEqual(expected)
          await waitForKnownHostsWrites()
          expect(await readFile(path, "utf8")).toBe(before)
        } finally {
          await chmod(path, 0o600)
        }
      }
    )

    it.each([
      { reason: "certificate-not-yet-valid", validity: "+1d:+2d" },
      { critical: true, reason: "certificate-critical-options" },
      { reason: "certificate-type-invalid", userCertificate: true },
    ])(
      "native connect cannot accept $reason even when the JS verifier returns true",
      async ({ reason, ...parameters }) => {
        await configure(parameters)
        const native = await loadNativeBinding()
        let calls = 0
        await expect(
          native.connect(
            {
              host: fixture().host,
              hostCertificates: true,
              port: fixture().ed25519Port,
              privateKey: await readFile(fixture().clientPrivateKeyPath),
              readyTimeoutMs: 5000,
              user: "paratix",
            },
            (info) => {
              calls += 1
              expect(info.kind).toBe("certificate")
              expect(info.certificateValidation).toStrictEqual({ reason, valid: false })
              return true
            }
          )
        ).rejects.toMatchObject({ code: "HOST_KEY_REJECTED", detail: reason })
        expect(calls).toBe(1)
      }
    )

    it("rejects an empty host principal list at the controller after native verification", async () => {
      await configure({ emptyPrincipals: true })
      await knownHosts()
      const native = await loadNativeBinding()
      const session = await native.connect(
        {
          host: fixture().host,
          hostCertificates: true,
          port: fixture().ed25519Port,
          privateKey: await readFile(fixture().clientPrivateKeyPath),
          readyTimeoutMs: 5000,
          user: "paratix",
        },
        (info) => {
          expect(info.principals).toStrictEqual([])
          expect(info.certificateValidation?.valid).toBe(true)
          return true
        }
      )
      await session.close()
      await expect(connect()).rejects.toThrow(/certificate validation or principal failed/v)
    })

    it("records OpenSSH loader refusal of a corrupted certificate signature before native verification", async () => {
      await configure({ invalidSignature: true })
      const diagnostic = await remote([
        "sh",
        "-c",
        "/usr/sbin/sshd -e -t -f /etc/ssh/sshd_config.ed25519 2>&1",
      ])
      expect(diagnostic).toMatch(/Could not load host certificate/v)
      await remote(["test", "-s", "/etc/ssh/ssh_host_ed25519_key-cert.pub"])
      const certificateScan = spawnSync(
        "ssh-keyscan",
        ["-c", "-T", "2", "-p", String(fixture().ed25519Port), fixture().host],
        { encoding: "utf8", timeout: 5000 }
      )
      expect(certificateScan.error).toBeUndefined()
      expect(certificateScan.stdout).not.toMatch(/-cert-v01@openssh.com /v)
      const native = await loadNativeBinding()
      const session = await native.connect(
        {
          host: fixture().host,
          hostCertificates: true,
          port: fixture().ed25519Port,
          privateKey: await readFile(fixture().clientPrivateKeyPath),
          readyTimeoutMs: 5000,
          user: "paratix",
        },
        (info) => {
          expect(info.kind).toBe("key")
          expect(info.certType).toBeUndefined()
          return true
        }
      )
      await session.close()
    })

    it("accepts a newly certified leaf at rsync time and blocks alternative-leaf revocations", async () => {
      await configure()
      await knownHosts()
      const ssh = await connect()
      const initial = ssh.getConnectionInfo().verifiedHostPublicKey
      await configure({ rotate: true })
      const rotated = await hostPublicKey()
      expect(rotated).not.toBe(initial)
      expect(await transfer(ssh)).toBeUndefined()
      await knownHosts(`@revoked [${fixture().host}]:${fixture().ed25519Port} ${rotated}\n`)
      expect(await transfer(ssh)).toMatch(/revoked|HOST IDENTIFICATION|verification failed/iv)
    })

    it.each([
      { label: "ca", revokedKey: () => authority },
      {
        label: "leaf",
        revokedKey: (ssh: SshConnectionImpl) => ssh.getConnectionInfo().verifiedHostPublicKey,
      },
    ])("blocks a freshly revoked session $label before rsync", async ({ revokedKey }) => {
      await configure()
      await knownHosts()
      const ssh = await connect()
      await knownHosts(`@revoked [${fixture().host}]:${fixture().ed25519Port} ${revokedKey(ssh)}\n`)
      expect(await transfer(ssh)).toContain("session trust anchor is revoked")
    })

    it.each([
      { principal: "foreign.example" },
      { ca: "/etc/ssh/foreign_ca" },
      { validity: "-2d:-1d" },
    ])("rejects invalid initial host certificates %#", async (parameters) => {
      await configure(parameters)
      await knownHosts()
      await expect(connect()).rejects.toThrow(/HOST KEY VERIFICATION FAILED/v)
    })

    it.each([{ principal: "foreign.example" }, { ca: "/etc/ssh/foreign_ca" }])(
      "rejects an invalid replacement certificate in real rsync %#",
      async (parameters) => {
        await configure()
        await knownHosts()
        const ssh = await connect()
        await configure(parameters)
        expect(await transfer(ssh)).toMatch(/verification failed/iv)
      }
    )

    it.each(["ed25519", "rsa"] as const)(
      "uses raw %s leaf algorithms for pinned certificates and fails on leaf rotation or certificate-only servers",
      async (algorithm) => {
        await configure({ algorithm })
        await knownHosts()
        const leaf = await hostPublicKey({ algorithm })
        const ssh = await connect(leaf)
        expect(await transfer(ssh)).toBeUndefined()
        await configure({ algorithm, certOnly: true })
        expect(await transfer(ssh)).toMatch(/no matching host key type|Unable to negotiate/iv)
        await configure({ algorithm, rotate: true })
        expect(await transfer(ssh)).toMatch(/HOST IDENTIFICATION|verification failed/iv)
      }
    )

    it.each([
      {
        getPin: undefined,
        hostilePath: "/etc/ssh/foreign_ca.pub",
        label: "CA",
        prefix: "@cert-authority ",
        rotate: false,
      },
      {
        getPin: (leaf: string) => leaf,
        hostilePath: "/etc/ssh/ssh_host_ed25519_key.pub",
        label: "pinned leaf",
        prefix: "",
        rotate: true,
      },
    ])(
      "disables inherited KnownHostsCommand and DNS trust in the $label path",
      async ({ getPin, hostilePath, prefix, rotate }) => {
        await configure()
        await knownHosts()
        const leaf = await hostPublicKey()
        const ssh = await connect(getPin?.(leaf))
        await configure({ ca: "/etc/ssh/foreign_ca", rotate })
        const label = `[${fixture().host}]:${fixture().ed25519Port}`
        const hostileKey = `${prefix}${label} ${await publicKey(hostilePath)}`
        const command = join(fixture().workspaceHome, "hostile-known-hosts")
        const marker = join(fixture().workspaceHome, "command-was-run")
        await writeFile(
          command,
          `#!/bin/sh\nprintf used > ${shellQuote(marker)}\nprintf '%s\\n' '${hostileKey}'\n`,
          { mode: 0o700 }
        )
        const configPath = join(fixture().workspaceHome, ".ssh", "config")
        const bin = join(fixture().workspaceHome, "controlled-bin")
        await mkdir(bin, { recursive: true })
        await writeFile(
          join(bin, "ssh"),
          `#!/bin/sh\nexec /usr/bin/ssh -F ${shellQuote(configPath)} "$@"\n`,
          { mode: 0o700 }
        )
        process.env.PATH = fixturePath(bin)
        await writeFile(
          configPath,
          `Host *\n  KnownHostsCommand ${command}\n  VerifyHostKeyDNS yes\n`
        )
        try {
          const baseline = spawnSync(
            "ssh",
            [
              "-F",
              configPath,
              "-p",
              String(fixture().ed25519Port),
              "-i",
              fixture().clientPrivateKeyPath,
              "-o",
              "IdentitiesOnly=yes",
              "-o",
              "StrictHostKeyChecking=yes",
              "-o",
              "UserKnownHostsFile=/dev/null",
              "-o",
              "GlobalKnownHostsFile=/dev/null",
              `paratix@${fixture().host}`,
              "true",
            ],
            { encoding: "utf8", timeout: 15_000 }
          )
          expect({ status: baseline.status, stderr: baseline.stderr }).toMatchObject({ status: 0 })
          await access(marker)
          await unlink(marker)
          expect(await transfer(ssh)).toMatch(/HOST IDENTIFICATION|verification failed/iv)
          await expect(access(marker)).rejects.toThrow(/ENOENT/v)
          const effective = spawnSync(
            "ssh",
            [
              "-G",
              "-F",
              configPath,
              "-o",
              "KnownHostsCommand=none",
              "-o",
              "VerifyHostKeyDNS=no",
              fixture().host,
            ],
            { encoding: "utf8" }
          )
          expect(effective.stdout).toContain("verifyhostkeydns false")
          expect(effective.stdout).not.toMatch(/^knownhostscommand /mv)
        } finally {
          await writeFile(configPath, "")
        }
      }
    )
  }
)
