/* oxlint-disable vitest/no-conditional-in-test -- Table-driven cases explicitly select fixture inputs and expected outcomes; every case runs its assertions. */
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { inspect } from "node:util"
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest"

import type { SshdConfigTransaction } from "../src/modules/sshd.js"
import type { HostTarget } from "../src/modules/sshHostCertificateTarget.js"
import type { HostCertificateSigner } from "../src/modules/sshHostCertificateTypes.js"
import type { FixtureKey } from "./helpers/hostCertificateFixtures.js"

import * as providerProcess from "../src/modules/opSpawnRunner.js"
import { secret } from "../src/modules/secret.js"
import { ssh } from "../src/modules/ssh.js"
import * as sshd from "../src/modules/sshd.js"
import * as commit from "../src/modules/sshHostCertificateCommit.js"
import * as pending from "../src/modules/sshHostCertificatePending.js"
import { parseHostCertificate } from "../src/modules/sshHostCertificatePolicy.js"
import * as recovery from "../src/modules/sshHostCertificateRecovery.js"
import * as target from "../src/modules/sshHostCertificateTarget.js"
import * as processes from "../src/modules/sshSignerProcess.js"
import {
  DAY,
  fixtureCertificate,
  fixtureKey,
  fixtureRequest,
  CERTIFICATE_NOW as NOW,
} from "./helpers/hostCertificateFixtures.js"
import { createMockSsh } from "./helpers/mockSsh.js"

let directory: string
let ca: FixtureKey
let host: FixtureKey
let acceptable: string
let tooLong: string
const MARKER = "marked-apply-signing-credential"

function snapshot(certificate: null | string): HostTarget {
  const config =
    "HostKey /etc/ssh/ssh_host_ed25519_key\nHostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub\n"
  return {
    certificate: certificate === null ? null : parseHostCertificate(certificate),
    certificateContent: certificate,
    certificateState:
      certificate === null ? null : { hash: "public-certificate-hash", metadata: "644 0 0" },
    configContent: config,
    configState: { hash: "config-hash", metadata: "644 0 0" },
    dependencies: [],
    desiredConfig: config,
    effective: `${config}HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com\n`,
    hostKeyState: { hash: "private-host-key-hash", metadata: "600 0 0" },
    publicKey: host.publicKey.trim().split(/\s+/v).slice(0, 2).join(" "),
  }
}

function boundary(certificate: null | string) {
  const connection = createMockSsh({})
  const transaction: SshdConfigTransaction = {
    connection,
    readEffective: vi.fn(),
    reload: vi.fn(),
    reloadOnly: vi.fn(),
    requireReloadOnly: vi.fn(),
    restoreReload: vi.fn(),
    validate: vi.fn(),
  }
  // The target inspection and prepared-commit seams are intentional outer doubles.
  // Real certificates, policy, temporal decisions and signer validation stay live.
  const inspectTarget = vi
    .spyOn(target, "inspectHostTarget")
    .mockResolvedValue(snapshot(certificate))
  vi.spyOn(pending, "hostPendingExists").mockResolvedValue(false)
  vi.spyOn(recovery, "recoverHostPending").mockResolvedValue("none")
  const transactionCall = vi
    .spyOn(sshd, "withSshdConfigTransaction")
    .mockImplementation(async (_connection, input) => input.section(transaction))
  const publish = vi.spyOn(commit, "repairOrCommit").mockResolvedValue({ status: "changed" })
  let now = NOW
  vi.spyOn(Date, "now").mockImplementation(() => now * 1000)
  return {
    advance(seconds: number) {
      now += seconds
    },
    connection,
    inspectTarget,
    publish,
    transaction,
    transactionCall,
  }
}
function signer(
  sign = vi.fn<HostCertificateSigner["sign"]>().mockResolvedValue(acceptable)
): HostCertificateSigner {
  return { caPublicKey: ca.publicKey, sign, version: 1 }
}

describe("sshHostCertificateApplyPolicy test context", () => {
  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), "paratix-apply-policy-test-"))
    ca = await fixtureKey(directory, "ca", "ed25519")
    host = await fixtureKey(directory, "host", "ed25519")
    acceptable = await fixtureCertificate(directory, ca, fixtureRequest(host.publicKey))
    tooLong = await fixtureCertificate(
      directory,
      ca,
      fixtureRequest(host.publicKey, { validAfter: NOW - 20 * DAY, validBefore: NOW + 10 * DAY })
    )
  })
  afterEach(() => vi.restoreAllMocks())
  afterAll(async () => rm(directory, { force: true, recursive: true }))

  describe("host certificate apply-time policy decisions", () => {
    it("returns ok on both applies, check and dry-run with zero signer/provider/commit/reload calls, including a validity extension", async () => {
      const b = boundary(acceptable)
      const provider = vi.spyOn(providerProcess, "spawnWithInput")
      const step = ssh.signer.stepCa({
        caPublicKey: ca.publicKey,
        caUrl: "https://ca.invalid",
        password: secret.provider("1password").deferred("op://private-test/item/password"),
        provisioner: "fixture",
        root: join(directory, "public-root"),
      })
      const sign = vi.fn(step.sign)
      const descriptor = { ...step, sign }
      for (const validity of ["14d", "30d"]) {
        const module = ssh.hostCertificate({
          principals: ["host.test", "192.0.2.1"],
          renewBefore: "7d",
          signer: descriptor,
          validity,
        })
        // eslint-disable-next-line no-await-in-loop -- Consecutive runs on one observed state prove idempotence and extension-only convergence.
        expect(await module.apply(b.connection, {})).toStrictEqual({ status: "ok" })
        // eslint-disable-next-line no-await-in-loop -- Consecutive runs on one observed state prove idempotence and extension-only convergence.
        expect(await module.apply(b.connection, {})).toStrictEqual({ status: "ok" })
        // eslint-disable-next-line no-await-in-loop -- Consecutive runs on one observed state prove idempotence and extension-only convergence.
        expect(await module.check(b.connection, {})).toBe("ok")
        // eslint-disable-next-line no-await-in-loop -- Consecutive runs on one observed state prove idempotence and extension-only convergence.
        expect(await module._applyDryRun?.(b.connection, {})).toStrictEqual({ status: "ok" })
      }
      expect(sign).not.toHaveBeenCalled()
      expect(provider).not.toHaveBeenCalled()
      expect(b.publish).not.toHaveBeenCalled()
      expect(b.transactionCall).not.toHaveBeenCalled()
      expect(b.transaction.reload).not.toHaveBeenCalled()
      expect(b.transaction.reloadOnly).not.toHaveBeenCalled()
      expect(b.connection.calls).toStrictEqual([])
      expect(b.connection.writeFileCalls).toStrictEqual([])
    })

    it("renews immediately for 30d original/10d remaining against 14d policy and exposes only a frozen public request", async () => {
      const b = boundary(tooLong)
      const descriptor = signer()
      const module = ssh.hostCertificate({
        principals: ["host.test", "192.0.2.1", "host.test"],
        renewBefore: "7d",
        signer: descriptor,
        validity: "14d",
      })
      expect(await module.apply(b.connection, {})).toStrictEqual({ status: "changed" })
      expect(descriptor.sign).toHaveBeenCalledTimes(1)
      const input = vi.mocked(descriptor.sign).mock.calls[0][0]
      expect(Object.isFrozen(input)).toBe(true)
      expect(Object.isFrozen(input.principals)).toBe(true)
      expect(input.principals).toStrictEqual(["192.0.2.1", "host.test"])
      expect(input.publicKey).toBe(snapshot(null).publicKey)
      expect(input.validAfter).toBe(NOW)
      expect(input.validBefore).toBe(NOW + 14 * DAY)
      expect(input.version).toBe(1)
      expect(input.signal).toBeInstanceOf(AbortSignal)
      expect(inspect(input)).not.toContain("PRIVATE KEY")
      expect(b.transaction.requireReloadOnly).toHaveBeenCalledTimes(1)
      expect(b.publish).toHaveBeenCalledExactlyOnceWith(
        b.connection,
        expect.objectContaining({ certificate: acceptable })
      )
    })

    it.each([
      [7 * DAY - 1, "changed"],
      [7 * DAY, "failed"],
      [7 * DAY + 1, "failed"],
    ])(
      "rechecks time advanced by %is during signing before publication",
      async (elapsed, status) => {
        const b = boundary(null)
        const sign = vi.fn<HostCertificateSigner["sign"]>().mockImplementation(async () => {
          b.advance(elapsed)
          await Promise.resolve()
          return acceptable
        })
        const module = ssh.hostCertificate({
          principals: ["host.test", "192.0.2.1"],
          renewBefore: "7d",
          signer: signer(sign),
          validity: "14d",
        })
        const result = await module.apply(b.connection, {})
        expect(result.status).toBe(status)
        expect(sign).toHaveBeenCalledTimes(1)
        expect(b.publish).toHaveBeenCalledTimes(status === "changed" ? 1 : 0)
      }
    )

    it("fails unsupported controller capabilities before provider access or publication", async () => {
      const b = boundary(null)
      const provider = vi.spyOn(providerProcess, "spawnWithInput")
      vi.spyOn(processes, "signerProcess").mockRejectedValue(new Error(MARKER))
      const descriptor = ssh.signer.stepCa({
        caPublicKey: ca.publicKey,
        caUrl: "https://ca.invalid",
        password: secret.provider("1password").deferred("op://private-test/item/password"),
        provisioner: "fixture",
        root: join(directory, "public-root"),
      })
      const module = ssh.hostCertificate({
        principals: ["host.test", "192.0.2.1"],
        renewBefore: "7d",
        signer: descriptor,
        validity: "14d",
      })
      const result = await module.apply(b.connection, {})
      expect(result.status).toBe("failed")
      expect(provider).not.toHaveBeenCalled()
      expect(b.publish).not.toHaveBeenCalled()
      expect(b.connection.writeFileCalls).toStrictEqual([])
      expect(inspect(result, { depth: null })).not.toContain(MARKER)
    })

    it("sanitizes custom signer failures and never retries an ambiguous request or publishes its output", async () => {
      const b = boundary(null)
      const sign = vi
        .fn<HostCertificateSigner["sign"]>()
        .mockRejectedValue(new Error(MARKER, { cause: new Error(MARKER) }))
      const module = ssh.hostCertificate({
        principals: ["host.test", "192.0.2.1"],
        renewBefore: "7d",
        signer: signer(sign),
        validity: "14d",
      })
      const result = await module.apply(b.connection, {})
      expect(result.status).toBe("failed")
      expect(inspect(result, { depth: null })).not.toContain(MARKER)
      expect(inspect(result, { depth: null })).toContain("not retried")
      expect(sign).toHaveBeenCalledTimes(1)
      expect(b.publish).not.toHaveBeenCalled()
    })

    it.each(["malformed", "too long", "empty"])(
      "rejects %s signer output before the commit seam",
      async (variant) => {
        const b = boundary(null)
        const sign = vi
          .fn<HostCertificateSigner["sign"]>()
          .mockResolvedValue(
            { empty: "", malformed: MARKER, "too long": tooLong }[variant] ?? MARKER
          )
        const module = ssh.hostCertificate({
          principals: ["host.test", "192.0.2.1"],
          renewBefore: "7d",
          signer: signer(sign),
          validity: "14d",
        })
        const result = await module.apply(b.connection, {})
        expect(result.status).toBe("failed")
        expect(inspect(result, { depth: null })).not.toContain(MARKER)
        expect(sign).toHaveBeenCalledTimes(1)
        expect(b.publish).not.toHaveBeenCalled()
      }
    )
  })
})
