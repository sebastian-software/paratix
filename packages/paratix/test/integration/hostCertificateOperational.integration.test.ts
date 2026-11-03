/* eslint-disable vitest/no-conditional-in-test -- Fault tables intentionally select the real failure boundary. */
/* oxlint-disable vitest/no-conditional-expect -- Fault tables exercise separate success and rejection contracts. */
/* oxlint-disable vitest/no-conditional-in-test -- Explicit fault-injection tables select a real boundary; all cases assert the same safety invariant. */
import { spawn, spawnSync } from "node:child_process"
import { readFile, writeFile } from "node:fs/promises"
import { join, resolve } from "node:path"
import { inspect } from "node:util"
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest"

import type {
  HostCertificateRequest,
  HostCertificateSigner,
} from "../../src/modules/sshHostCertificateTypes.js"

import * as providerProcess from "../../src/modules/opSpawnRunner.js"
import { secret } from "../../src/modules/secret.js"
import { ssh } from "../../src/modules/ssh.js"
import { sshd } from "../../src/modules/sshd.js"
import { parseHostCertificate } from "../../src/modules/sshHostCertificatePolicy.js"
import { SshConnectionImpl } from "../../src/ssh.js"
import { sshdCommitBody } from "../helpers/sshdCommitBody.js"
import { createTrustFixture, trustCommand, type TrustFixture } from "./certificateTrustHarness.js"
import {
  createStepFixture,
  STEP_PASSWORD,
  STEP_REFERENCE,
  type StepFixture,
} from "./stepCaHarness.js"

const available = spawnSync("docker", ["info"], { stdio: "ignore", timeout: 30_000 }).status === 0
if (!available && process.env.CI === "true")
  throw new Error("Host operational proofs require Docker in CI")
const CERT = "/etc/ssh/ssh_host_ed25519_key-cert.pub"
const CONFIG = "/etc/ssh/sshd_config"
const PENDING = "/var/lib/paratix/host-certificate-pending"
const HOLDER = "/var/lib/paratix/flags/etc-ssh-sshd-config-mutex/holder"
let fixture: TrustFixture
let step: StepFixture | undefined
let local: HostCertificateSigner

async function activeState(): Promise<string> {
  return fixture.container([
    "sh",
    "-c",
    `sha256sum '${CONFIG}' /etc/ssh/ssh_host_ed25519_key; test ! -e '${CERT}' || sha256sum '${CERT}'; stat -c '%a %u %g' '${CONFIG}' /etc/ssh/ssh_host_ed25519_key; test ! -e '${CERT}' || stat -c '%a %u %g' '${CERT}'; test ! -e /run/confirmed-reloads || cat /run/confirmed-reloads`,
  ])
}
function moduleFor(signer = local, principals = ["host.test"], validity = "1d") {
  return ssh.hostCertificate({ principals, renewBefore: "1h", signer, validity })
}
async function requireChanged(signer = local, principals = ["host.test"]): Promise<void> {
  const result = await moduleFor(signer, principals).apply(fixture.ssh, {})
  expect(result.error?.message).toBeUndefined()
  expect(result.status).toBe("changed")
}
async function pending(): Promise<Record<string, unknown>> {
  return JSON.parse(await fixture.ssh.readFile(PENDING)) as Record<string, unknown>
}
async function ageLease(): Promise<void> {
  await fixture.container([
    "sh",
    "-c",
    `test ! -e '${HOLDER}' || touch -d '5 minutes ago' '${HOLDER}'`,
  ])
}
async function crash(checkpoint: string): Promise<void> {
  const info = fixture.ssh.getConnectionInfo()
  await new Promise<void>((resolveExit, reject) => {
    const child = spawn(
      process.execPath,
      ["--import", "tsx", resolve(import.meta.dirname, "hostCertificateCrashWorker.ts")],
      {
        cwd: resolve(import.meta.dirname, "../.."),
        env: {
          ...process.env,
          PARATIX_HOST_CRASH_INPUT: JSON.stringify({
            bootstrap: info.privateKeyPath,
            caKey: join(fixture.directory, "operational-ca"),
            checkpoint,
            hostKey: info.verifiedHostPublicKey,
            port: info.port,
          }),
        },
        stdio: ["ignore", "pipe", "pipe"],
      }
    )
    const errors: Buffer[] = []
    child.stderr.on("data", (value: Buffer) => {
      errors.push(value)
    })
    child.on("error", reject)
    const timeout = setTimeout(() => {
      child.kill("SIGKILL")
      reject(new Error(`Crash checkpoint timed out: ${checkpoint}`))
    }, 60_000)
    child.on("close", (code, signal) => {
      clearTimeout(timeout)
      if (signal === "SIGKILL") resolveExit()
      else
        reject(
          new Error(
            `Crash checkpoint ${checkpoint} not reached (${String(code)}): ${Buffer.concat(errors).toString()}`
          )
        )
    })
  })
  await ageLease()
}
async function strictCertificate(principal = "host.test", ca = local.caPublicKey): Promise<string> {
  const info = fixture.ssh.getConnectionInfo()
  const known = join(fixture.directory, "strict-known-hosts")
  await writeFile(known, `@cert-authority ${principal} ${ca.trim()}\n`, { mode: 0o600 })
  if (info.privateKeyPath === undefined) throw new Error("Missing bootstrap identity")
  // -vv prints the certificate fingerprint/serial actually offered by the running main daemon.
  return trustCommand("ssh", [
    "-F",
    "/dev/null",
    "-p",
    String(info.port),
    "-i",
    info.privateKeyPath,
    "-o",
    "CertificateFile=none",
    "-o",
    "IdentityAgent=none",
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    "BatchMode=yes",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    `UserKnownHostsFile=${known}`,
    "-o",
    "GlobalKnownHostsFile=/dev/null",
    "-o",
    `HostKeyAlias=${principal}`,
    "-o",
    "HostKeyAlgorithms=ssh-ed25519-cert-v01@openssh.com",
    "-o",
    "ConnectTimeout=5",
    "root@127.0.0.1",
    "id -un",
  ])
}
async function assertMainCertificate(
  principal = "host.test",
  ca = local.caPublicKey
): Promise<void> {
  expect(await strictCertificate(principal, ca)).toBe("root")
  const keyscan = await trustCommand("ssh-keyscan", [
    "-c",
    "-p",
    String(fixture.ssh.getConnectionInfo().port),
    "-t",
    "ed25519",
    "127.0.0.1",
  ])
  const activeCertificate = await fixture.ssh.readFile(CERT)
  const active = activeCertificate.trim().split(/\s+/v).slice(0, 2).join(" ")
  expect(
    keyscan
      .split("\n")
      .find((line) => line.startsWith("ssh-ed25519-cert-v01@openssh.com "))
      ?.trim()
      .split(/\s+/v)
      .slice(0, 2)
      .join(" ")
  ).toBe(active)
}

async function connectCompetitor(): Promise<SshConnectionImpl> {
  const info = fixture.ssh.getConnectionInfo()
  if (info.privateKeyPath === undefined || info.verifiedHostPublicKey === undefined)
    throw new Error("Incomplete isolated bootstrap identity")
  const connection = new SshConnectionImpl("127.0.0.1", {
    expectedHostPublicKey: info.verifiedHostPublicKey,
    ports: [info.port, 22],
    privateKey: info.privateKeyPath,
    strictHostKeyChecking: "yes",
    user: "root",
  })
  await connection.connect()
  return connection
}

function isWriterFault(writer: string, body: string, observations: string[]): boolean {
  if (writer === "principals")
    return (
      body.startsWith("su -s /bin/sh -c") &&
      observations.some(
        (observation) =>
          observation.includes("mv -T --") &&
          observation.includes("'/etc/ssh/auth_principals/deploy'")
      )
    )
  return false
}

function missingCheckpoint(): never {
  throw new Error("Missing process checkpoint")
}
function matchesPauseBoundary(command: string, boundary: string): boolean {
  const fragments: Record<string, string[]> = {
    "before-marker": ["/manifest-next'", "mv -T --", "'/var/lib/paratix/host-certificate-pending'"],
    "during-publish": ['mv -T -- "$paratix_copy"', "'/etc/ssh/ssh_host_ed25519_key-cert.pub'"],
    "during-reload": ["\nsystemctl reload ssh"],
  }
  return fragments[boundary].every((fragment) => command.includes(fragment))
}
function injectTargetPause(command: string, boundary: string): string {
  const pause = 'printf "%s" "$$" > /run/host-paused-pid; kill -STOP $$'
  if (boundary === "before-marker")
    return command.replace(
      "# paratix-sshd-commit-body",
      () => `# paratix-sshd-commit-body\n${pause}`
    )
  if (boundary === "during-publish")
    return command.replace(
      "mv -T -- \"$paratix_copy\" '/etc/ssh/ssh_host_ed25519_key-cert.pub'",
      () => `mv -T -- "$paratix_copy" '${CERT}'\n${pause}`
    )
  return `${command}\n${pause}`
}

describe.skipIf(!available)(
  "host certificate operational boundaries",
  { concurrent: false },
  () => {
    beforeAll(async () => {
      fixture = await createTrustFixture(resolve(import.meta.dirname, "../.."))
      const caKey = join(fixture.directory, "operational-ca")
      await trustCommand("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", caKey])
      local = ssh.signer.local({ caKey, caPublicKey: await readFile(`${caKey}.pub`, "utf8") })
    })
    beforeEach(async () => {
      await fixture.container([
        "sh",
        "-c",
        `rm -rf /var/lib/paratix/host-certificate-pending /var/lib/paratix/host-certificate-state-* /var/lib/paratix/flags/etc-ssh-sshd-config-mutex; rm -f '${CERT}' /run/no-reload`,
      ])
      await fixture.reset()
    })
    afterEach(() => {
      vi.restoreAllMocks()
      vi.unstubAllEnvs()
    })
    afterAll(async () => {
      await step?.cleanup()
      await fixture.cleanup()
    })

    it("renews unchanged configuration with one reload and preserves the main process and host private key", async () => {
      await requireChanged()
      const config = await fixture.ssh.readFile(CONFIG)
      const pid = await fixture.container(["cat", "/run/main-sshd.pid"])
      const privateState = await fixture.container([
        "sh",
        "-c",
        "sha256sum /etc/ssh/ssh_host_ed25519_key; stat -c '%a %u %g' /etc/ssh/ssh_host_ed25519_key",
      ])
      const old = await fixture.ssh.readFile(CERT)
      await fixture.container(["rm", "/run/confirmed-reloads"])
      await requireChanged(local, ["renewed.test"])
      expect(await fixture.ssh.readFile(CONFIG)).toBe(config)
      expect(await fixture.ssh.readFile(CERT)).not.toBe(old)
      const reloads = await fixture.container(["cat", "/run/confirmed-reloads"])
      expect(reloads.split("\n")).toHaveLength(1)
      expect(await fixture.container(["cat", "/run/main-sshd.pid"])).toBe(pid)
      expect(
        await fixture.container([
          "sh",
          "-c",
          "sha256sum /etc/ssh/ssh_host_ed25519_key; stat -c '%a %u %g' /etc/ssh/ssh_host_ed25519_key",
        ])
      ).toBe(privateState)
      await assertMainCertificate("renewed.test")
      await expect(strictCertificate("host.test")).rejects.toThrow(/ssh failed/v)
      await expect(strictCertificate("renewed.test", fixture.ca2)).rejects.toThrow(/ssh failed/v)
    })

    it("repairs safe certificate metadata without signing or reloading", async () => {
      await requireChanged()
      await fixture.container(["chmod", "0600", CERT])
      await fixture.container(["rm", "/run/confirmed-reloads"])
      const sign = vi.fn(local.sign)
      await requireChanged({ ...local, sign })
      expect(sign).not.toHaveBeenCalled()
      expect(await fixture.container(["stat", "-c", "%a %u %g", CERT])).toBe("644 0 0")
      expect(await fixture.ssh.exists("/run/confirmed-reloads")).toBe(false)
    })

    it.each(["raw-only", "wrong-host-key", "malformed-config", "no-reload"])(
      "rejects %s before any active mutation",
      async (kind) => {
        const initialConfig = await fixture.ssh.readFile(CONFIG)
        if (kind === "raw-only")
          await fixture.write(
            CONFIG,
            `HostKeyAlgorithms ssh-ed25519\n${await fixture.ssh.readFile(CONFIG)}`
          )
        if (kind === "wrong-host-key")
          await fixture.write(
            CONFIG,
            initialConfig.replace(
              "HostKey /etc/ssh/ssh_host_ed25519_key",
              "HostKey /etc/ssh/ssh_host_rsa_key"
            )
          )
        if (kind === "malformed-config")
          await fixture.write(
            CONFIG,
            `InvalidParatixDirective yes\n${await fixture.ssh.readFile(CONFIG)}`
          )
        if (kind === "no-reload") await fixture.container(["touch", "/run/no-reload"])
        const before = await activeState()
        const result = await moduleFor().apply(fixture.ssh, {})
        expect(result.status).toBe("failed")
        expect(await activeState()).toBe(before)
        expect(await fixture.ssh.exists(PENDING)).toBe(false)
      }
    )

    it("rejects an existing competing certificate mapping for the selected host key before signing", async () => {
      await requireChanged()
      const certificate = await fixture.ssh.readFile(CERT)
      await fixture.write("/etc/ssh/competing-cert.pub", certificate)
      const config = await fixture.ssh.readFile(CONFIG)
      await fixture.write(
        CONFIG,
        config.replace(`HostCertificate ${CERT}`, "HostCertificate /etc/ssh/competing-cert.pub")
      )
      const sign = vi.fn(local.sign)
      const before = await activeState()
      const result = await moduleFor({ ...local, sign }).apply(fixture.ssh, {})
      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("Another active certificate")
      expect(sign).not.toHaveBeenCalled()
      expect(await activeState()).toBe(before)
    })

    it.each([
      "before-active",
      "between-publishes",
      "after-config",
      "before-reload",
      "after-reload",
      "before-complete",
      "after-complete",
      "cleanup-1",
      "cleanup-2",
      "cleanup-3",
      "cleanup-directory",
    ])(
      "recovers a real SIGKILL at %s without signing or files-only success",
      async (checkpoint) => {
        await crash(checkpoint)
        expect(await fixture.ssh.exists(PENDING)).toBe(true)
        const sign = vi.fn(local.sign)
        const module = moduleFor({ ...local, sign })
        const before = await activeState()
        const marker = await fixture.ssh.readFile(PENDING)
        expect(await module.check(fixture.ssh, {})).toBe("needs-apply")
        const dryRun = await module._applyDryRun?.(fixture.ssh, {})
        expect(dryRun?.status).toBe("changed")
        expect(await activeState()).toBe(before)
        expect(await fixture.ssh.readFile(PENDING)).toBe(marker)
        const result = await module.apply(fixture.ssh, {})
        expect(result.error?.message).toBeUndefined()
        expect(result.status).toBe("changed")
        expect(sign).not.toHaveBeenCalled()
        expect(await fixture.ssh.exists(PENDING)).toBe(false)
        await assertMainCertificate()
      }
    )

    it.each([
      "version",
      "corrupt",
      "insecure",
      "foreign-active",
      "missing-snapshot",
      "host-key-conflict",
      "missing-active",
      "snapshot-hash",
      "unsafe-directory",
    ])("fails closed on %s Pending evidence without overwriting it", async (kind) => {
      await crash("between-publishes")
      const manifest = await pending()
      if (kind === "version")
        await fixture.write(PENDING, JSON.stringify({ ...manifest, version: 999 }), "0600")
      if (kind === "corrupt") await fixture.write(PENDING, "{broken", "0600")
      if (kind === "insecure") await fixture.container(["chmod", "0644", PENDING])
      if (kind === "foreign-active") await fixture.write(CERT, "foreign certificate evidence")
      if (kind === "missing-snapshot")
        await fixture.container([
          "rm",
          `/var/lib/paratix/host-certificate-state-${String(manifest.id)}/original-config`,
        ])
      if (kind === "host-key-conflict")
        await fixture.container(["chmod", "0400", "/etc/ssh/ssh_host_ed25519_key"])
      if (kind === "missing-active") await fixture.container(["rm", CONFIG])
      if (kind === "snapshot-hash")
        await fixture.write(
          `/var/lib/paratix/host-certificate-state-${String(manifest.id)}/candidate-certificate`,
          "foreign snapshot evidence",
          "0600"
        )
      if (kind === "unsafe-directory")
        await fixture.container([
          "chmod",
          "0755",
          `/var/lib/paratix/host-certificate-state-${String(manifest.id)}`,
        ])
      const before = await activeState()
      const marker = await fixture.ssh.readFile(PENDING)
      const sign = vi.fn(local.sign)
      const result = await moduleFor({ ...local, sign }).apply(fixture.ssh, {})
      expect(result.status).toBe("failed")
      expect(sign).not.toHaveBeenCalled()
      expect(await activeState()).toBe(before)
      expect(await fixture.ssh.readFile(PENDING)).toBe(marker)
      await fixture.container(["chmod", "0600", "/etc/ssh/ssh_host_ed25519_key"])
    })

    it.each(["principals", "validity", "ca"])(
      "resolves changed %s Pending policy before issuing a replacement",
      async (kind) => {
        await crash("between-publishes")
        const oldConfig = await fixture.container(["cat", "/run/initial-sshd-config"])
        const signer =
          kind === "ca"
            ? ssh.signer.local({ caKey: join(fixture.directory, "ca2"), caPublicKey: fixture.ca2 })
            : local
        const sign = vi.fn(async (request: HostCertificateRequest) => {
          expect(await fixture.ssh.exists(PENDING)).toBe(false)
          const restoredConfig = await fixture.ssh.readFile(CONFIG)
          expect(restoredConfig.trim()).toBe(oldConfig.trim())
          expect(await fixture.ssh.exists(CERT)).toBe(false)
          return signer.sign(request)
        })
        const module = moduleFor(
          { ...signer, sign },
          kind === "principals" ? ["replacement.test"] : ["host.test"],
          kind === "validity" ? "12h" : "1d"
        )
        const result = await module.apply(fixture.ssh, {})
        expect(result.error?.message).toBeUndefined()
        expect(result.status).toBe("changed")
        expect(sign).toHaveBeenCalledTimes(1)
        await assertMainCertificate(
          kind === "principals" ? "replacement.test" : "host.test",
          signer.caPublicKey
        )
      }
    )

    it("retains rollback evidence after reload failure and resumes a repeatable rollback", async () => {
      const beforeConfig = await fixture.ssh.readFile(CONFIG)
      await fixture.container(["touch", "/run/fail-all-reloads"])
      const failed = await moduleFor().apply(fixture.ssh, {})
      expect(failed.status).toBe("failed")
      expect(failed.error?.message).toContain("Pending evidence retained")
      const retained = await pending()
      expect(retained.phase).toBe("rollback")
      expect(await fixture.ssh.readFile(CONFIG)).toBe(beforeConfig)
      expect(await fixture.ssh.exists(CERT)).toBe(false)
      await fixture.container(["rm", "/run/fail-all-reloads"])
      const result = await moduleFor().apply(fixture.ssh, {})
      expect(result.error?.message).toBeUndefined()
      expect(result.status).toBe("changed")
      await assertMainCertificate()
    })

    it.each(["stage", "publish", "effective", "reload"])(
      "rolls back an ordinary %s failure with verified old files and a live daemon",
      async (fault) => {
        await requireChanged(local, ["old.test"])
        const oldConfig = await fixture.ssh.readFile(CONFIG)
        const oldCertificate = await fixture.ssh.readFile(CERT)
        await fixture.container(["rm", "/run/confirmed-reloads"])
        if (fault === "reload") await fixture.container(["touch", "/run/fail-reload-once"])
        const execute = fixture.ssh.exec.bind(fixture.ssh)
        let injected = false
        vi.spyOn(fixture.ssh, "exec").mockImplementation(async (command, options) => {
          const boundary =
            (fault === "stage" && command.includes("sshd -t -f")) ||
            (fault === "publish" &&
              command.includes('mv -T -- "$paratix_copy"') &&
              command.includes("'/etc/ssh/sshd_config'")) ||
            (fault === "effective" &&
              command.endsWith("\nsshd -T") &&
              (await fixture.ssh.exists(PENDING)))
          if (!injected && boundary) {
            injected = true
            return { code: 1, stderr: "Injected operational boundary failure", stdout: "" }
          }
          return execute(command, options)
        })
        const result = await moduleFor().apply(fixture.ssh, {})
        expect(result.status).toBe("failed")
        expect(fault === "reload" || injected).toBe(true)
        expect(await fixture.ssh.readFile(CONFIG)).toBe(oldConfig)
        expect(await fixture.ssh.readFile(CERT)).toBe(oldCertificate)
        expect(await fixture.ssh.exists(PENDING)).toBe(false)
        await assertMainCertificate("old.test")
      }
    )

    it.each(["rollback-certificate", "rollback-config"])(
      "repeats immutable multi-file restoration after SIGKILL at %s",
      async (checkpoint) => {
        await requireChanged(local, ["old.test"])
        const oldCertificate = await fixture.ssh.readFile(CERT)
        await fixture.container([
          "sh",
          "-c",
          "cp /run/initial-sshd-config /etc/ssh/sshd_config; systemctl reload ssh; rm -f /run/confirmed-reloads; touch /run/fail-reload-once",
        ])
        const oldConfig = await fixture.ssh.readFile(CONFIG)
        await crash(checkpoint)
        const manifest = await pending()
        expect(manifest.phase).toBe("rollback")
        const directory = `/var/lib/paratix/host-certificate-state-${String(manifest.id)}`
        expect(await fixture.ssh.readFile(`${directory}/original-certificate`)).toBe(oldCertificate)
        expect(await fixture.ssh.readFile(`${directory}/original-config`)).toBe(oldConfig)
        const sign = vi.fn(async (request: HostCertificateRequest) => {
          expect(await fixture.ssh.exists(PENDING)).toBe(false)
          expect(await fixture.ssh.readFile(CONFIG)).toBe(oldConfig)
          expect(await fixture.ssh.readFile(CERT)).toBe(oldCertificate)
          return local.sign(request)
        })
        await requireChanged({ ...local, sign })
        expect(sign).toHaveBeenCalledTimes(1)
        await assertMainCertificate()
      }
    )

    it.each(["before-complete-old", "after-complete-old"])(
      "recovers SIGKILL at %s without consuming original snapshots",
      async (checkpoint) => {
        await requireChanged(local, ["old.test"])
        const oldCertificate = await fixture.ssh.readFile(CERT)
        await fixture.container(["touch", "/run/fail-reload-once"])
        await crash(checkpoint)
        const manifest = await pending()
        expect(["rollback", "complete-old"]).toContain(manifest.phase)
        expect(await fixture.ssh.readFile(CERT)).toBe(oldCertificate)
        const sign = vi.fn(async (request: HostCertificateRequest) => {
          expect(await fixture.ssh.exists(PENDING)).toBe(false)
          expect(await fixture.ssh.readFile(CERT)).toBe(oldCertificate)
          return local.sign(request)
        })
        await requireChanged({ ...local, sign })
        expect(sign).toHaveBeenCalledTimes(1)
        await assertMainCertificate()
      }
    )

    it("converges after SIGKILL immediately following the final completed marker unlink", async () => {
      await crash("cleanup-marker")
      expect(await fixture.ssh.exists(PENDING)).toBe(false)
      const sign = vi.fn(local.sign)
      const result = await moduleFor({ ...local, sign }).apply(fixture.ssh, {})
      expect(result.status).toBe("ok")
      expect(sign).not.toHaveBeenCalled()
      await assertMainCertificate()
    })

    it.each(["cleanup-4", "cleanup-5"])(
      "finishes renewal cleanup after a real process kill at %s",
      async (checkpoint) => {
        await requireChanged(local, ["old.test"])
        await crash(checkpoint)
        const retained = await pending()
        expect(retained.phase).toBe("complete-new")
        const sign = vi.fn(local.sign)
        await requireChanged({ ...local, sign })
        expect(sign).not.toHaveBeenCalled()
        await assertMainCertificate()
      }
    )

    it("restores an expired candidate before requesting a new certificate", async () => {
      await crash("between-publishes")
      const future = Date.now() + 2 * 86_400_000
      vi.spyOn(Date, "now").mockReturnValue(future)
      const sign = vi.fn(async (request: HostCertificateRequest) => {
        expect(await fixture.ssh.exists(PENDING)).toBe(false)
        expect(await fixture.ssh.exists(CERT)).toBe(false)
        return local.sign(request)
      })
      await requireChanged({ ...local, sign })
      expect(sign).toHaveBeenCalledTimes(1)
    })

    it.each(["wrong-key", "malformed"])(
      "rejects %s signer output without active changes",
      async (kind) => {
        const before = await activeState()
        const sign = vi.fn(async (request: HostCertificateRequest) =>
          kind === "malformed"
            ? "not a certificate"
            : local.sign({ ...request, publicKey: fixture.ca2 })
        )
        const result = await moduleFor({ ...local, sign }).apply(fixture.ssh, {})
        expect(result.status).toBe("failed")
        expect(await activeState()).toBe(before)
        expect(await fixture.ssh.exists(PENDING)).toBe(false)
      }
    )

    it.each([
      { advance: 1, expected: "changed", lifetime: 7200, name: "shorter accepted" },
      { advance: 1, expected: "failed", lifetime: 3601, name: "exact threshold rejected" },
      { advance: 2, expected: "failed", lifetime: 3601, name: "below threshold rejected" },
      { advance: 0, expected: "failed", lifetime: 86_401, name: "total lifespan exceeded" },
    ])(
      "validates real cryptographic output after time progresses: $name",
      async ({ advance, expected, lifetime }) => {
        let now = Math.floor(Date.now() / 1000) * 1000
        vi.spyOn(Date, "now").mockImplementation(() => now)
        const before = await activeState()
        const sign = vi.fn(async (request: HostCertificateRequest) => {
          const certificate = await local.sign({
            ...request,
            validBefore: request.validAfter + lifetime,
          })
          now += advance * 1000
          return certificate
        })
        const result = await moduleFor({ ...local, sign }).apply(fixture.ssh, {})
        expect(result.status).toBe(expected)
        if (expected === "failed") expect(await activeState()).toBe(before)
        else {
          expect(
            parseHostCertificate(await fixture.ssh.readFile(CERT)).validBefore -
              parseHostCertificate(await fixture.ssh.readFile(CERT)).validAfter
          ).toBe(lifetime)
          await assertMainCertificate()
        }
      }
    )

    it("preserves foreign certificate mappings, Includes and the exact algorithm policy while validating the complete candidate first", async () => {
      const publicKey = await fixture.container(["cat", "/etc/ssh/ssh_host_rsa_key.pub"])
      const now = Math.floor(Date.now() / 1000)
      const foreign = await local.sign({
        principals: ["foreign.test"],
        publicKey,
        requestId: "foreign-certificate",
        signal: new AbortController().signal,
        validAfter: now,
        validBefore: now + 86_400,
        version: 1,
      })
      await fixture.write("/etc/ssh/foreign-cert.pub", foreign)
      await fixture.container(["mkdir", "-p", "/etc/ssh/conf.d"])
      const include =
        "HostKey /etc/ssh/ssh_host_rsa_key\nHostCertificate /etc/ssh/foreign-cert.pub\nHostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com\n"
      await fixture.write("/etc/ssh/conf.d/foreign.conf", include)
      await fixture.write(
        CONFIG,
        `Include /etc/ssh/conf.d/*.conf\n${await fixture.ssh.readFile(CONFIG)}`
      )
      const calls: string[] = []
      const execute = fixture.ssh.exec.bind(fixture.ssh)
      vi.spyOn(fixture.ssh, "exec").mockImplementation(async (command, options) => {
        calls.push(command)
        return execute(command, options)
      })
      await requireChanged()
      expect(await fixture.ssh.readFile("/etc/ssh/conf.d/foreign.conf")).toBe(include)
      expect(await fixture.ssh.readFile("/etc/ssh/foreign-cert.pub")).toBe(foreign)
      const publication = calls.findIndex(
        (command) => command.includes("mv -T --") && command.includes("/manifest-next'")
      )
      expect(publication).toBeGreaterThan(0)
      expect(calls.slice(0, publication).some((command) => command.includes("sshd -t -f"))).toBe(
        true
      )
      expect(calls.slice(0, publication).some((command) => command.includes("sshd -T -f"))).toBe(
        true
      )
      await assertMainCertificate()
    })

    it("discards a stale response when another host run already converged", async () => {
      let release: () => void = missingCheckpoint
      let entered: () => void = missingCheckpoint
      const gate = new Promise<void>((resolveGate) => {
        release = resolveGate
      })
      const reached = new Promise<void>((resolveReached) => {
        entered = resolveReached
      })
      const sign = vi.fn(async (request: HostCertificateRequest) => {
        const certificate = await local.sign(request)
        entered()
        await gate
        return certificate
      })
      const first = moduleFor({ ...local, sign }).apply(fixture.ssh, {})
      await reached
      try {
        await requireChanged()
        const converged = await activeState()
        release()
        const result = await first
        expect(result.status).toBe("ok")
        expect(await activeState()).toBe(converged)
        expect(sign).toHaveBeenCalledTimes(1)
        await assertMainCertificate()
      } finally {
        release()
        await first
      }
    })

    it("preserves successful config, user CA and principal writes made during controller signing", async () => {
      const sign = vi.fn(async (request: HostCertificateRequest) => {
        const certificate = await local.sign(request)
        const configResult = await sshd.config({ MaxAuthTries: "4" }).apply(fixture.ssh, {})
        expect(configResult.status).toBe("changed")
        const principalResult = await ssh
          .authorizedPrincipals("deploy", ["release-team"])
          .apply(fixture.ssh, {})
        expect(principalResult.status).toBe("changed")
        const ca = await ssh.trustedUserCa({ publicKey: fixture.ca1 }).apply(fixture.ssh, {})
        expect(ca.error?.message).toBeUndefined()
        expect(ca.status).toBe("changed")
        return certificate
      })
      await requireChanged({ ...local, sign })
      expect(await fixture.ssh.readFile(CONFIG)).toContain("MaxAuthTries 4")
      expect(await fixture.ssh.readFile(CONFIG)).toContain(
        "TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys"
      )
      const trustedCa = await fixture.ssh.readFile("/etc/ssh/trusted_user_ca_keys")
      expect(trustedCa.trim()).toBe(fixture.ca1.trim())
      expect(await fixture.ssh.readFile("/etc/ssh/auth_principals/deploy")).toBe("release-team\n")
      await assertMainCertificate()
    })

    it("rejects a stale signer response after a real host-key replacement without overwriting that replacement", async () => {
      await fixture.container(["cp", "/etc/ssh/ssh_host_ed25519_key", "/run/original-host-key"])
      await fixture.container([
        "cp",
        "/etc/ssh/ssh_host_ed25519_key.pub",
        "/run/original-host-key.pub",
      ])
      let replacement = ""
      const sign = vi.fn(async (request: HostCertificateRequest) => {
        const certificate = await local.sign(request)
        await fixture.container([
          "sh",
          "-c",
          "rm /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key.pub; ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key",
        ])
        replacement = await activeState()
        return certificate
      })
      try {
        const result = await moduleFor({ ...local, sign }).apply(fixture.ssh, {})
        expect(result.status).toBe("failed")
        expect(result.error?.message).toContain("Host key changed during controller signing")
        expect(await activeState()).toBe(replacement)
        expect(await fixture.ssh.exists(PENDING)).toBe(false)
      } finally {
        await fixture.container([
          "sh",
          "-c",
          "mv /run/original-host-key /etc/ssh/ssh_host_ed25519_key; mv /run/original-host-key.pub /etc/ssh/ssh_host_ed25519_key.pub",
        ])
      }
    })

    it.each(["config", "port", "user-ca", "principals"] as const)(
      "holds the target kernel lock through %s publication and rollback",
      async (writer) => {
        await fixture.container(["rm", "-f", "/run/writer-kernel-proofs"])
        if (writer === "principals") {
          await fixture.container(["mkdir", "-p", "/etc/ssh/auth_principals"])
          await fixture.write("/etc/ssh/auth_principals/deploy", "before\n")
        }
        if (writer === "config" || writer === "user-ca")
          await fixture.container(["touch", "/run/fail-reload-once"])
        const originalConfig = await fixture.ssh.readFile(CONFIG)
        const info = fixture.ssh.getConnectionInfo()
        vi.spyOn(fixture.ssh, "getConnectionInfo").mockReturnValue({
          ...info,
          configuredPorts: [...info.configuredPorts, 2233],
        })
        const modules = {
          config: sshd.config({ MaxAuthTries: "4" }),
          port: sshd.port(2233),
          principals: ssh.authorizedPrincipals("deploy", ["after"]),
          "user-ca": ssh.trustedUserCa({ publicKey: fixture.ca1 }),
        }
        const execute = fixture.ssh.exec.bind(fixture.ssh)
        const observations: string[] = []
        let injected = false
        vi.spyOn(fixture.ssh, "exec").mockImplementation(async (command, options) => {
          const body = sshdCommitBody(command)
          const mutation =
            /\b(?:mv|cp|rm|chmod|chown|mkdir|rmdir)\b/v.test(body) && body.includes("/etc/ssh/")
          const service = /systemctl (?:reload|restart) ssh$/v.test(body)
          let actual = command
          if (mutation || service) {
            expect(command).toContain("# paratix-sshd-commit-body")
            observations.push(body)
            const proof = `test "$(readlink /proc/$$/fd/9)" = /var/lib/paratix/sshd-commit.lock || exit 89
if flock -n /var/lib/paratix/sshd-commit.lock true; then exit 89; fi
printf 'held\\n' >> /run/writer-kernel-proofs`
            actual = command.replace(
              "# paratix-sshd-commit-body",
              () => `# paratix-sshd-commit-body\n${proof}`
            )
          }
          const execution = await execute(actual, options)
          if (!injected && isWriterFault(writer, body, observations)) {
            injected = true
            return { code: 1, stderr: "Injected post-publication failure", stdout: "" }
          }
          expect(execution.code).not.toBe(89)
          return execution
        })
        const result = await modules[writer].apply(fixture.ssh, {})
        expect(result.status).toBe("failed")
        if (writer === "port")
          expect(observations.some((body) => body.endsWith("systemctl restart ssh"))).toBe(true)
        expect(
          observations.filter((body) => body.includes("mv -T --")).length
        ).toBeGreaterThanOrEqual(2)
        const proofs = await fixture.container(["cat", "/run/writer-kernel-proofs"])
        expect(proofs.split("\n")).toHaveLength(observations.length)
        expect(await fixture.ssh.readFile(CONFIG)).toBe(originalConfig)
        if (writer === "principals")
          expect(await fixture.ssh.readFile("/etc/ssh/auth_principals/deploy")).toBe("before\n")
        if (writer === "user-ca")
          expect(await fixture.ssh.exists("/etc/ssh/trusted_user_ca_keys")).toBe(false)
      }
    )

    it.each(["before-marker", "during-publish", "during-reload"])(
      "keeps the living target OS lock at %s beyond lease expiry against every sshd writer",
      async (boundary) => {
        const competitors = await Promise.all(Array.from({ length: 4 }, connectCompetitor))
        const execute = fixture.ssh.exec.bind(fixture.ssh)
        const fences: number[] = []
        let paused = false
        let resumeController: () => void = missingCheckpoint
        const controllerGate = new Promise<void>((resolveGate) => {
          resumeController = resolveGate
        })
        vi.spyOn(fixture.ssh, "exec").mockImplementation(async (command, options) => {
          if (paused || !matchesPauseBoundary(command, boundary)) {
            const commandResult = await execute(command, options)
            if (
              commandResult.code === 74 &&
              commandResult.stderr.includes("Stale sshd controller lease")
            )
              fences.push(commandResult.code)
            return commandResult
          }
          paused = true
          const injected = injectTargetPause(command, boundary)
          const result = await execute(injected, options).catch((error: unknown) => ({ error }))
          await controllerGate
          if ("error" in result) throw result.error
          return result
        })
        const controller = moduleFor().apply(fixture.ssh, {})
        let targetPid: string | undefined
        try {
          await fixture.container([
            "timeout",
            "20",
            "sh",
            "-c",
            "until test -s /run/host-paused-pid && grep -q '^State:.*T' /proc/$(cat /run/host-paused-pid)/status; do sleep 0.02; done",
          ])
          targetPid = await fixture.container(["cat", "/run/host-paused-pid"])
          expect(
            await fixture.container([
              "sh",
              "-c",
              `awk '/^State:/{print $2}' /proc/${targetPid}/status`,
            ])
          ).toBe("T")
          const holder = await fixture.ssh.readFile(HOLDER)
          await ageLease()
          const before = await activeState()
          const modules = [
            sshd.config({ MaxAuthTries: "4" }),
            sshd.port(22),
            ssh.trustedUserCa({ publicKey: fixture.ca1 }),
            ssh.authorizedPrincipals("deploy", ["release-team"]),
          ]
          const started = performance.now()
          const results = await Promise.allSettled(
            modules.map(async (module, index) => module.apply(competitors[index], {}))
          )
          // Independent controllers avoid the four-channel cap of one shared transport.
          // Each live kernel-lock attempt has the product's explicit flock -w 30 deadline.
          expect(performance.now() - started).toBeLessThan(45_000)
          expect(results).toHaveLength(4)
          for (const result of results) {
            expect(result.status).toBe("fulfilled")
            if (result.status === "fulfilled") expect(result.value.status).toBe("failed")
          }
          expect(await activeState()).toBe(before)
          expect(await fixture.ssh.readFile(HOLDER)).toBe(holder)
          expect(
            await fixture.container([
              "sh",
              "-c",
              `awk '/^State:/{print $2}' /proc/${targetPid}/status`,
            ])
          ).toBe("T")
          await fixture.container(["kill", "-KILL", targetPid])
          targetPid = undefined
          // Only after actual process death can another process take the kernel lock.
          await fixture.container([
            "flock",
            "-x",
            "-w",
            "3",
            "/var/lib/paratix/sshd-commit.lock",
            "sh",
            "-c",
            `printf 'successful-foreign-controller\\n' > '${HOLDER}'`,
          ])
          resumeController()
          const staleResult = await controller
          expect(staleResult.status).toBe("failed")
          expect(fences.length).toBeGreaterThan(0)
          expect(await activeState()).toBe(before)
          expect(await fixture.ssh.readFile(HOLDER)).toBe("successful-foreign-controller\n")
        } finally {
          if (targetPid !== undefined) await fixture.container(["kill", "-KILL", targetPid])
          resumeController()
          await controller
          for (const competitor of competitors) competitor.disconnect()
          await fixture.container(["rm", "-f", "/run/host-paused-pid"])
        }
      }
    )

    it("runs the real isolated JWK/TLS Step CA and never sends signer credentials to the target", async () => {
      step = await createStepFixture()
      vi.stubEnv("PATH", `${step.directory}:${process.env.PATH ?? ""}`)
      const provider = vi.spyOn(providerProcess, "spawnWithInput").mockResolvedValue(STEP_PASSWORD)
      const calls: string[] = []
      const execute = fixture.ssh.exec.bind(fixture.ssh)
      vi.spyOn(fixture.ssh, "exec").mockImplementation(async (command, options) => {
        calls.push(command)
        return execute(command, options)
      })
      const signer = ssh.signer.stepCa({
        caPublicKey: step.caPublicKey,
        caUrl: "https://127.0.0.1:9000",
        password: secret.provider("1password").deferred(STEP_REFERENCE),
        provisioner: "paratix-jwk",
        root: step.root,
      })
      const result = await moduleFor(signer).apply(fixture.ssh, {})
      expect(result.error?.message).toBeUndefined()
      expect(result.status).toBe("changed")
      expect(provider).toHaveBeenCalledTimes(1)
      await assertMainCertificate("host.test", step.caPublicKey)
      const evidence = `${inspect(result, { depth: null })}\n${calls.join("\n")}\n${await readFile(join(step.directory, "argv.jsonl"), "utf8")}\n${await fixture.container(["sh", "-c", "find /var/lib/paratix /etc/ssh -type f -not -name 'ssh_host_*key' -exec cat {} +"])}`
      expect(evidence).not.toContain(STEP_PASSWORD)
      expect(evidence).not.toContain(STEP_REFERENCE)
      provider.mockClear()
      const converged = await moduleFor(signer).apply(fixture.ssh, {})
      expect(converged.status).toBe("ok")
      expect(provider).not.toHaveBeenCalled()

      for (const failure of ["password", "tls", "ca-limit"]) {
        if (failure === "password") provider.mockResolvedValue("marked-wrong-jwk-password")
        else provider.mockResolvedValue(STEP_PASSWORD)
        const badSigner = ssh.signer.stepCa({
          caPublicKey: step.caPublicKey,
          caUrl: "https://127.0.0.1:9000",
          password: secret.provider("1password").deferred(STEP_REFERENCE),
          provisioner: "paratix-jwk",
          root: failure === "tls" ? step.wrongRoot : step.root,
        })
        // eslint-disable-next-line no-await-in-loop -- Sequential CA failures each snapshot the unchanged target.
        const before = await activeState()
        // eslint-disable-next-line no-await-in-loop -- Reuse the isolated CA without racing password-provider settings.
        const failureResult = await moduleFor(
          badSigner,
          ["different.test"],
          failure === "ca-limit" ? "3d" : "1d"
        ).apply(fixture.ssh, {})
        expect(failureResult.status).toBe("failed")
        expect(inspect(failureResult, { depth: null })).not.toContain(STEP_PASSWORD)
        expect(inspect(failureResult, { depth: null })).not.toContain("marked-wrong-jwk-password")
        // eslint-disable-next-line no-await-in-loop -- Confirm this CA failure preserved the snapshot before the next case.
        expect(await activeState()).toBe(before)
      }

      const shorter = {
        ...signer,
        sign: async (request: HostCertificateRequest) =>
          signer.sign({ ...request, validBefore: request.validAfter + 7200 }),
      }
      const shortened = await moduleFor(shorter, ["shorter.test"]).apply(fixture.ssh, {})
      expect(shortened.error?.message).toBeUndefined()
      expect(shortened.status).toBe("changed")
      const shortCertificate = parseHostCertificate(await fixture.ssh.readFile(CERT))
      expect(shortCertificate.validBefore - shortCertificate.validAfter).toBe(7200)
      await assertMainCertificate("shorter.test", step.caPublicKey)
      const unchanged = await activeState()
      const frozen = Math.floor(Date.now() / 1000) * 1000
      vi.spyOn(Date, "now").mockReturnValue(frozen)
      const thresholdSigner = {
        ...signer,
        sign: async (request: HostCertificateRequest) =>
          signer.sign({ ...request, validBefore: request.validAfter + 3600 }),
      }
      const threshold = await moduleFor(thresholdSigner, ["threshold.test"]).apply(fixture.ssh, {})
      expect(threshold.status).toBe("failed")
      expect(await activeState()).toBe(unchanged)
      const finalTrace = `${calls.join("\n")}\n${await readFile(join(step.directory, "argv.jsonl"), "utf8")}`
      for (const marker of [STEP_PASSWORD, STEP_REFERENCE, "marked-wrong-jwk-password"])
        expect(finalTrace).not.toContain(marker)
      expect(finalTrace).not.toContain("--context")
      expect(finalTrace).not.toContain("bootstrap")
      const issued = parseHostCertificate(await fixture.ssh.readFile(CERT))
      expect(issued.validBefore - issued.validAfter).toBe(7200)
    })
  }
)
