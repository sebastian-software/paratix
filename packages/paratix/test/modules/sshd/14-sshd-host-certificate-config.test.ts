import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest"

import type { HostCertificatePolicy } from "../../../src/modules/sshHostCertificatePolicy.js"

import * as config from "../../../src/modules/sshCertificateConfig.js"
import { hostCertificate } from "../../../src/modules/sshHostCertificate.js"
import {
  collectHostDirectivePaths,
  hostDirectivePath,
} from "../../../src/modules/sshHostCertificateConfig.js"
import * as pending from "../../../src/modules/sshHostCertificatePending.js"
import { parseHostCertificate } from "../../../src/modules/sshHostCertificatePolicy.js"
import {
  assertHostAlgorithms,
  convergedHostTarget,
  inspectHostTarget,
} from "../../../src/modules/sshHostCertificateTarget.js"
import { HostCertificateError } from "../../../src/modules/sshSignerProcess.js"
import {
  CERTIFICATE_NOW,
  DAY,
  fixtureCertificate,
  fixtureKey,
  fixtureRequest,
} from "../../helpers/hostCertificateFixtures.js"
import { createMockSsh } from "../../helpers/mockSsh.js"

const ROOT = "/etc/ssh/sshd_config"
const KEY = "/etc/ssh/ssh_host_ed25519_key"
const CERTIFICATE = `${KEY}-cert.pub`
const FOREIGN = "/etc/ssh/foreign-cert.pub"
const ALGORITHMS = "HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com\n"
let directory: string
let policy: HostCertificatePolicy
let certificate: string
let publicKey: string

function targetSsh(effective: string, overrides: Record<string, { stdout: string }> = {}) {
  return createMockSsh(
    {
      [`cat '${CERTIFICATE}'`]: { stdout: certificate },
      [`cat '${FOREIGN}'`]: { stdout: certificate },
      [`cat '${ROOT}'`]: { stdout: effective },
      [`ssh-keygen -y -P '' -f '${KEY}' </dev/null`]: { stdout: publicKey },
      [`stat -c '%a %u %g' -- '${CERTIFICATE}'`]: { stdout: "644 0 0" },
      [`stat -c '%a %u %g' -- '${KEY}'`]: { stdout: "600 0 0" },
      "sshd -T": { stdout: `${effective}\n${ALGORITHMS}` },
      ...overrides,
    },
    {
      responseStubs: [
        { command: /^\[ -L /v, result: { code: 1 } },
        { command: /^\[ -[edf] /v, result: { code: 0 } },
        { command: /^stat -c '%a %u %g' -- /v, result: { stdout: "755 0 0" } },
        { command: /^stat -c '%h' -- /v, result: { stdout: "1" } },
        { command: /^sha256sum /v, result: { stdout: "hash  file" } },
      ],
    }
  )
}

describe("host certificate directive paths", () => {
  afterEach(() => vi.restoreAllMocks())

  it.each(["none", "none # note", "none\t#note"])(
    "keeps unquoted lowercase %j as the HostCertificate absence sentinel",
    (value) => {
      expect(hostDirectivePath("HostCertificate", value)).toBeNull()
      expect(
        collectHostDirectivePaths(`HostCertificate ${value}`, "HostCertificate")
      ).toStrictEqual([])
      expect(hostDirectivePath("HostKey", value)).toBe("none")
    }
  )

  it.each(['"none"', "'none'", "None", "NONE"])(
    "does not broaden the absence sentinel for %j",
    (value) => {
      expect(hostDirectivePath("HostCertificate", `${value} # note`)).toBe(
        value.replaceAll(/^["']|["']$/gv, "")
      )
    }
  )

  it.each(["HostCertificate", "HostKey"] as const)(
    "rejects an empty effective %s directive",
    (directive) => {
      expect(() => collectHostDirectivePaths(`${directive}\n`, directive)).toThrow(
        HostCertificateError
      )
    }
  )

  it("leaves unexpected parser exceptions untouched", () => {
    const unexpected = new Error("unexpected parser failure")
    vi.spyOn(config, "parseCertificateFileArgument").mockImplementation(() => {
      throw unexpected
    })
    expect(() => hostDirectivePath("HostCertificate", CERTIFICATE)).toThrow(unexpected)
  })
})

describe("host certificate inspection and effective algorithms", () => {
  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), "paratix-host-config-"))
    const ca = await fixtureKey(directory, "ca", "ed25519")
    const host = await fixtureKey(directory, "host", "ed25519")
    publicKey = host.publicKey.trim().split(/\s+/v).slice(0, 2).join(" ")
    certificate = await fixtureCertificate(directory, ca, fixtureRequest(publicKey))
    policy = {
      caPublicKey: parseHostCertificate(certificate).caPublicKey,
      certificatePath: CERTIFICATE,
      hostKeyPath: KEY,
      keyType: "ed25519",
      principals: ["192.0.2.1", "host.test"],
      renewBefore: DAY,
      validity: 14 * DAY,
    }
  })
  afterEach(() => vi.restoreAllMocks())
  afterAll(async () => rm(directory, { force: true, recursive: true }))

  it.each([
    `HostKey ${KEY} # note\nHostCertificate ${CERTIFICATE} # managed`,
    `HostKey "${KEY}" # note\nHostCertificate '${CERTIFICATE}' # managed`.toLowerCase(),
  ])("recognizes and converges commented mappings %j", async (effective) => {
    const ssh = targetSsh(effective)
    const target = await inspectHostTarget(ssh, policy)
    expect(target.desiredConfig).toBe(target.configContent)
    expect(convergedHostTarget(target, policy, CERTIFICATE_NOW)).toBe(true)
    expect(ssh.calls.some((command) => command.includes("#"))).toBe(false)
  })

  it.each([
    ["HostKey", KEY, "one unambiguous effective HostKey mapping"],
    ["HostCertificate", CERTIFICATE, "Ambiguous active HostCertificate mapping"],
  ])("rejects duplicate commented and plain %s mappings", async (directive, path, message) => {
    const effective = `HostKey ${KEY}\nHostCertificate ${CERTIFICATE}\n${directive} ${path} # duplicate`
    await expect(inspectHostTarget(targetSsh(effective), policy)).rejects.toThrow(message)
  })

  it("checks a foreign commented certificate at its filename and rejects a competing mapping", async () => {
    const ssh = targetSsh(`HostKey ${KEY}\nHostCertificate ${FOREIGN} # foreign`)
    await expect(inspectHostTarget(ssh, policy)).rejects.toThrow(
      "Another active certificate already maps to the selected host key"
    )
    expect(ssh.calls).toContain(`cat '${FOREIGN}'`)
    expect(ssh.calls.some((command) => command.includes("#"))).toBe(false)
  })

  it("checks a literal mid-token hash as part of the foreign filename", async () => {
    const path = "/etc/ssh/foreign#1.pub"
    const ssh = targetSsh(`HostKey ${KEY}\nHostCertificate ${path} # foreign`, {
      [`cat '${path}'`]: { stdout: certificate },
    })
    await expect(inspectHostTarget(ssh, policy)).rejects.toThrow(
      "Another active certificate already maps to the selected host key"
    )
    expect(ssh.calls).toContain(`cat '${path}'`)
  })

  it("rejects a commented HostKey overlapping the certificate destination", async () => {
    const effective = `HostKey ${KEY}\nHostKey ${CERTIFICATE} # overlap`
    await expect(inspectHostTarget(targetSsh(effective), policy)).rejects.toThrow(
      "Certificate destination overlaps another sshd resource"
    )
  })

  describe.each(["HostCertificate", "HostKey"] as const)("%s parsing", (directive) => {
    it.each([
      '/etc/ssh/"key"',
      String.raw`/etc/ssh/key\name`,
      '"/etc/ssh/key',
      '""',
      "# note",
      `${CERTIFICATE} /etc/ssh/other`,
    ])("fails closed before reading unresolved filename %j", async (value) => {
      const ssh = targetSsh(`HostKey ${KEY}\n${directive} ${value}`)
      await expect(inspectHostTarget(ssh, policy)).rejects.toThrow(HostCertificateError)
      expect(ssh.calls.filter((command) => command.startsWith("cat "))).toStrictEqual([
        `cat '${ROOT}'`,
      ])
    })
  })

  it.each(["HostCertificate", "HostKey"] as const)(
    "validates %s paths in the effective algorithm check",
    (directive) => {
      const effective = `HostKey ${KEY} # note\nHostCertificate ${CERTIFICATE} # managed\n${ALGORITHMS}`
      expect(() => {
        assertHostAlgorithms(effective, parseHostCertificate(certificate), {
          policy,
          stagedPath: CERTIFICATE,
        })
      }).not.toThrow()
      expect(() => {
        assertHostAlgorithms(
          `${effective}${directive} /etc/ssh/"ambiguous"\n`,
          parseHostCertificate(certificate),
          { policy, stagedPath: CERTIFICATE }
        )
      }).toThrow(HostCertificateError)
    }
  )

  it.each(["HostCertificate", "HostKey"] as const)(
    "reports expected %s parse failures through public dry-run and apply without signing",
    async (directive) => {
      vi.spyOn(pending, "hostPendingExists").mockResolvedValue(false)
      const sign = vi.fn()
      const module = hostCertificate({
        principals: policy.principals,
        signer: { caPublicKey: policy.caPublicKey, sign, version: 1 },
      })
      const ssh = targetSsh(`HostKey ${KEY}\n${directive} /etc/ssh/"ambiguous"`)
      const expected = {
        error: {
          message: expect.stringContaining(`Cannot safely resolve sshd ${directive}`),
        },
        status: "failed",
      }
      await expect(module._applyDryRun?.(ssh, {})).resolves.toMatchObject(expected)
      await expect(module.apply(ssh, {})).resolves.toMatchObject(expected)
      expect(sign).not.toHaveBeenCalled()
      expect(ssh.writeFileCalls).toStrictEqual([])
    }
  )

  it("masks unexpected parser exceptions in the public dry-run", async () => {
    vi.spyOn(pending, "hostPendingExists").mockResolvedValue(false)
    vi.spyOn(config, "parseCertificateFileArgument").mockImplementation(() => {
      throw new Error("private unexpected diagnostic")
    })
    const module = hostCertificate({
      principals: policy.principals,
      signer: { caPublicKey: policy.caPublicKey, sign: vi.fn(), version: 1 },
    })
    await expect(module._applyDryRun?.(targetSsh(`HostKey ${KEY}`), {})).resolves.toMatchObject({
      error: { message: "[ssh.hostCertificate] Public state inspection failed" },
      status: "failed",
    })
  })
})
