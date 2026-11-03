import { spawn, spawnSync } from "node:child_process"
import { readFile, writeFile } from "node:fs/promises"
import { join, resolve } from "node:path"
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest"

import * as providerProcess from "../../src/modules/opSpawnRunner.js"
import { secret } from "../../src/modules/secret.js"
import { ssh } from "../../src/modules/ssh.js"
import * as controllerProcess from "../../src/modules/sshSignerProcess.js"
import { createTrustFixture, trustCommand, type TrustFixture } from "./certificateTrustHarness.js"

const available = spawnSync("docker", ["info"], { stdio: "ignore", timeout: 30_000 }).status === 0
if (!available && process.env.CI === "true")
  throw new Error("Host certificate proofs require Docker in CI")
let fixture: TrustFixture | undefined
function target(): TrustFixture {
  if (fixture === undefined) throw new Error("Missing host fixture")
  return fixture
}

async function strictProbe(ca: string, principal = "host.test"): Promise<string> {
  const info = target().ssh.getConnectionInfo()
  const knownHosts = join(target().directory, "host-known-hosts")
  await writeFile(knownHosts, `@cert-authority ${principal} ${ca.trim()}\n`, { mode: 0o600 })
  if (info.privateKeyPath === undefined) throw new Error("Missing bootstrap private key")
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
    `UserKnownHostsFile=${knownHosts}`,
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

async function crashController(caKey: string): Promise<null | string> {
  const info = target().ssh.getConnectionInfo()
  return new Promise((resolveExit, reject) => {
    const child = spawn(
      process.execPath,
      ["--import", "tsx", resolve(import.meta.dirname, "hostCertificateCrashWorker.ts")],
      {
        cwd: resolve(import.meta.dirname, "../.."),
        env: {
          ...process.env,
          PARATIX_HOST_CRASH_INPUT: JSON.stringify({
            bootstrap: info.privateKeyPath,
            caKey,
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
    child.on("close", (code, signal) => {
      if (signal === "SIGKILL") resolveExit(signal)
      else
        reject(
          new Error(
            `Crash worker did not reach checkpoint (${String(code)}): ${Buffer.concat(errors).toString()}`
          )
        )
    })
  })
}

describe.skipIf(!available)(
  "controller-issued SSH host certificates",
  { concurrent: false },
  () => {
    beforeAll(async () => {
      fixture = await createTrustFixture(resolve(import.meta.dirname, "../.."))
    })
    afterEach(() => {
      vi.restoreAllMocks()
    })
    afterAll(async () => {
      await fixture?.cleanup()
    })

    it("publishes a real certificate, reloads only the main daemon and converges without signing", async () => {
      const caKey = join(target().directory, "host-ca")
      await trustCommand("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", caKey])
      const signer = ssh.signer.local({
        caKey,
        caPublicKey: await readFile(`${caKey}.pub`, "utf8"),
      })
      const sign = vi.fn(signer.sign)
      const module = ssh.hostCertificate({
        principals: ["host.test"],
        renewBefore: "1h",
        signer: { ...signer, sign },
        validity: "1d",
      })
      const hostBefore = await target().container(["sha256sum", "/etc/ssh/ssh_host_ed25519_key"])
      const pidBefore = await target().container(["cat", "/run/main-sshd.pid"])
      expect(await module.check(target().ssh, {})).toBe("needs-apply")
      const dryRun = await module._applyDryRun?.(target().ssh, {})
      expect(dryRun?.status).toBe("changed")
      expect(sign).not.toHaveBeenCalled()
      const first = await module.apply(target().ssh, {})
      expect(first.error?.message).toBeUndefined()
      expect(first.status).toBe("changed")
      expect(sign).toHaveBeenCalledTimes(1)
      expect(await strictProbe(await readFile(`${caKey}.pub`, "utf8"))).toBe("root")
      await expect(strictProbe(target().ca2)).rejects.toThrow(
        /host key ssh-ed25519 not permitted by HostkeyAlgorithms|Host key verification failed/v
      )
      await expect(
        strictProbe(await readFile(`${caKey}.pub`, "utf8"), "wrong.test")
      ).rejects.toThrow(
        /host key ssh-ed25519 not permitted by HostkeyAlgorithms|Host key verification failed/v
      )
      expect(await module.check(target().ssh, {})).toBe("ok")
      const convergedApply = await module.apply(target().ssh, {})
      expect(convergedApply.status).toBe("ok")
      const convergedDryRun = await module._applyDryRun?.(target().ssh, {})
      expect(convergedDryRun?.status).toBe("ok")
      expect(sign).toHaveBeenCalledTimes(1)
      expect(await target().container(["sha256sum", "/etc/ssh/ssh_host_ed25519_key"])).toBe(
        hostBefore
      )
      expect(await target().container(["cat", "/run/main-sshd.pid"])).toBe(pidBefore)
      expect(
        await target().container([
          "sh",
          "-c",
          "test ! -e /var/lib/paratix/host-certificate-pending && echo cleaned",
        ])
      ).toBe("cleaned")
      expect(await target().container(["cat", "/run/confirmed-reloads"])).toBe(
        `${pidBefore} absent`
      )
    })
    it("recovers a killed controller between certificate publication and config/reload without signing again", async () => {
      await target().reset()
      await target().container(["rm", "-f", "/etc/ssh/ssh_host_ed25519_key-cert.pub"])
      const caKey = join(target().directory, "host-ca")
      const caPublicKey = await readFile(`${caKey}.pub`, "utf8")
      const before = await target().container(["sha256sum", "/etc/ssh/ssh_host_ed25519_key"])
      expect(await crashController(caKey)).toBe("SIGKILL")
      expect(
        await target().container([
          "sh",
          "-c",
          "test -f /var/lib/paratix/host-certificate-pending && echo pending",
        ])
      ).toBe("pending")
      // Advance the controller lease clock, not the OS lock; the killed target process has ended.
      // This avoids waiting two wall-clock minutes in every deterministic crash proof.
      await target().container([
        "touch",
        "-d",
        "5 minutes ago",
        "/var/lib/paratix/flags/etc-ssh-sshd-config-mutex/holder",
      ])
      const sign = vi
        .fn<() => Promise<string>>()
        .mockRejectedValue(new Error("Recovery must not request a new certificate"))
      const module = ssh.hostCertificate({
        principals: ["host.test"],
        renewBefore: "1h",
        signer: { caPublicKey, sign, version: 1 },
        validity: "1d",
      })
      expect(await module.check(target().ssh, {})).toBe("needs-apply")
      const dryRun = await module._applyDryRun?.(target().ssh, {})
      expect(dryRun?.status).toBe("changed")
      const result = await module.apply(target().ssh, {})
      expect(result.error?.message).toBeUndefined()
      expect(result.status).toBe("changed")
      expect(sign).not.toHaveBeenCalled()
      expect(await strictProbe(caPublicKey)).toBe("root")
      expect(await target().container(["sha256sum", "/etc/ssh/ssh_host_ed25519_key"])).toBe(before)
      expect(await module.check(target().ssh, {})).toBe("ok")
    })
    it("rejects incompatible controller tools before provider access or any active target mutation", async () => {
      await target().reset()
      const caKey = join(target().directory, "capability-target-ca")
      await trustCommand("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", caKey])
      const initial = ssh.hostCertificate({
        principals: ["original.test"],
        signer: ssh.signer.local({ caKey, caPublicKey: await readFile(`${caKey}.pub`, "utf8") }),
      })
      const installed = await initial.apply(target().ssh, {})
      expect(installed.error?.message).toBeUndefined()
      expect(installed.status).toBe("changed")
      const snapshot = async (): Promise<string> =>
        target().container([
          "sh",
          "-c",
          "sha256sum /etc/ssh/sshd_config /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key-cert.pub; stat -c '%a %u %g' /etc/ssh/sshd_config /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key-cert.pub; cat /run/confirmed-reloads",
        ])
      const before = await snapshot()
      const process = vi
        .spyOn(controllerProcess, "signerProcess")
        .mockRejectedValue(new Error("unsafe-tool-output-sentinel"))
      const provider = vi.spyOn(providerProcess, "spawnWithInput")
      const module = ssh.hostCertificate({
        principals: ["replacement.test"],
        signer: ssh.signer.stepCa({
          caPublicKey: target().ca2,
          caUrl: "https://ca.invalid",
          password: secret.provider("1password").deferred("op://capability-test/item/password"),
          provisioner: "test-provisioner",
          root: join(target().directory, "public-root.pem"),
        }),
      })
      const result = await module.apply(target().ssh, {})
      expect(result.status).toBe("failed")
      expect(result.error?.message).not.toContain("unsafe-tool-output-sentinel")
      expect(process).toHaveBeenCalledTimes(1)
      expect(provider).not.toHaveBeenCalled()
      expect(await snapshot()).toBe(before)
      expect(await target().ssh.exists("/var/lib/paratix/host-certificate-pending")).toBe(false)
    })
  }
)
