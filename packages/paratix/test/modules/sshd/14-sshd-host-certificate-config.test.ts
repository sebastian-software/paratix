import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest"

import type { HostCertificatePolicy } from "../../../src/modules/sshHostCertificatePolicy.js"

import * as config from "../../../src/modules/sshCertificateConfig.js"
import { hostCertificate } from "../../../src/modules/sshHostCertificate.js"
import {
  collectEffectiveHostDirectivePaths,
  hostDirectivePath,
} from "../../../src/modules/sshHostCertificateConfig.js"
import * as pending from "../../../src/modules/sshHostCertificatePending.js"
import { parseHostCertificate } from "../../../src/modules/sshHostCertificatePolicy.js"
import { validateHostCandidate } from "../../../src/modules/sshHostCertificateStaging.js"
import {
  assertHostAlgorithms,
  convergedHostTarget,
  inspectHostTarget,
} from "../../../src/modules/sshHostCertificateTarget.js"
import { HostCertificateError } from "../../../src/modules/sshSignerProcess.js"
import { shellQuote } from "../../../src/ssh.js"
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
const LITERAL_PATHS = [
  "/etc/ssh/foreign certificate.pub",
  "/etc/ssh/foreign #old.pub",
  "/etc/ssh/foreign#1.pub",
  '/etc/ssh/foreign "old".pub',
  "/etc/ssh/foreign 'old'.pub",
  String.raw`/etc/ssh/foreign\old.pub`,
  "/etc/ssh/foreign.pub ",
]
let directory: string
let policy: HostCertificatePolicy
let certificate: string
let publicKey: string

function targetSsh(effective: string, overrides: Record<string, { stdout: string }> = {}) {
  return createMockSsh(
    {
      [`cat '${CERTIFICATE}'`]: { stdout: certificate },
      [`cat '${FOREIGN}'`]: { stdout: certificate },
      [`cat '${ROOT}'`]: { stdout: `HostKey ${KEY}\nHostCertificate ${CERTIFICATE}\n` },
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
      expect(hostDirectivePath("HostKey", value)).toBe("none")
    }
  )

  it.each(LITERAL_PATHS)("preserves the decoded effective filename %j", (path) => {
    expect(
      collectEffectiveHostDirectivePaths(`HostCertificate ${path}\n`, "HostCertificate")
    ).toStrictEqual([path])
    expect(collectEffectiveHostDirectivePaths(`hostkey ${path}\n`, "HostKey")).toStrictEqual([path])
  })

  it("only skips the exact effective HostCertificate absence sentinel", () => {
    expect(
      collectEffectiveHostDirectivePaths("HostCertificate none\n", "HostCertificate")
    ).toStrictEqual([])
    for (const path of ['"none"', "'none'", "None", "NONE", "none # note", "none "]) {
      expect(
        collectEffectiveHostDirectivePaths(`HostCertificate ${path}\n`, "HostCertificate")
      ).toStrictEqual([path])
    }
    expect(collectEffectiveHostDirectivePaths("hostkey none\n", "HostKey")).toStrictEqual(["none"])
  })

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
      expect(() => collectEffectiveHostDirectivePaths(`${directive}\n`, directive)).toThrow(
        HostCertificateError
      )
    }
  )

  describe.each(["HostCertificate", "HostKey"] as const)("%s source parsing", (directive) => {
    it.each([
      '/etc/ssh/"key"',
      String.raw`/etc/ssh/key\name`,
      '"/etc/ssh/key',
      '""',
      "# note",
      `${CERTIFICATE} /etc/ssh/other`,
    ])("still fails closed for unresolved source argument %j", (value) => {
      expect(() => hostDirectivePath(directive, value)).toThrow(HostCertificateError)
    })
  })

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
  ])("recognizes commented source mappings with decoded effective paths %j", async (content) => {
    const ssh = targetSsh(`hostkey ${KEY}\nHostCertificate ${CERTIFICATE}`, {
      [`cat '${ROOT}'`]: { stdout: content },
    })
    const target = await inspectHostTarget(ssh, policy)
    expect(target.desiredConfig).toBe(target.configContent)
    expect(convergedHostTarget(target, policy, CERTIFICATE_NOW)).toBe(true)
    expect(ssh.calls.some((command) => command.includes("#"))).toBe(false)
  })

  it.each([
    ["HostKey", KEY, "one unambiguous effective HostKey mapping"],
    ["HostCertificate", CERTIFICATE, "Ambiguous active HostCertificate mapping"],
  ])("rejects duplicate effective %s mappings", async (directive, path, message) => {
    const effective = `HostKey ${KEY}\nHostCertificate ${CERTIFICATE}\n${directive} ${path}`
    await expect(inspectHostTarget(targetSsh(effective), policy)).rejects.toThrow(message)
  })

  it("checks a foreign certificate at its filename and rejects a competing mapping", async () => {
    const ssh = targetSsh(`HostKey ${KEY}\nHostCertificate ${FOREIGN}`)
    await expect(inspectHostTarget(ssh, policy)).rejects.toThrow(
      "Another active certificate already maps to the selected host key"
    )
    expect(ssh.calls).toContain(`cat '${FOREIGN}'`)
    expect(ssh.calls.some((command) => command.includes("#"))).toBe(false)
  })

  it.each(LITERAL_PATHS)(
    "rejects a competing certificate at the exact literal filename %j",
    async (path) => {
      const ssh = targetSsh(`hostkey ${KEY}\nHostCertificate ${path}`, {
        [`cat ${shellQuote(path)}`]: { stdout: certificate },
      })
      await expect(inspectHostTarget(ssh, policy)).rejects.toThrow(
        "Another active certificate already maps to the selected host key"
      )
      expect(ssh.calls).toContain(`cat ${shellQuote(path)}`)
    }
  )

  it("rejects an effective HostKey overlapping the certificate destination", async () => {
    const effective = `HostKey ${KEY}\nHostKey ${CERTIFICATE}`
    await expect(inspectHostTarget(targetSsh(effective), policy)).rejects.toThrow(
      "Certificate destination overlaps another sshd resource"
    )
  })

  it.each(LITERAL_PATHS)(
    "inspects unrelated literal key and certificate filenames %j",
    async (path) => {
      const ssh = targetSsh(
        `hostkey ${KEY}\nhostkey ${path}\nHostCertificate ${CERTIFICATE}\nHostCertificate ${path}`,
        {
          [`cat ${shellQuote(path)}`]: { stdout: "unrelated certificate" },
        }
      )
      const target = await inspectHostTarget(ssh, policy)
      expect(target.desiredConfig).toBe(target.configContent)
      expect(convergedHostTarget(target, policy, CERTIFICATE_NOW)).toBe(true)
      expect(ssh.calls).toContain(`cat ${shellQuote(path)}`)
    }
  )

  it.each(LITERAL_PATHS)(
    "accepts unrelated literal paths in the effective algorithm check: %j",
    (path) => {
      const effective = `hostkey ${KEY}\nHostCertificate ${CERTIFICATE}\nhostkey ${path}\nHostCertificate ${path}\n${ALGORITHMS}`
      expect(() => {
        assertHostAlgorithms(effective, parseHostCertificate(certificate), {
          policy,
          stagedPath: CERTIFICATE,
        })
      }).not.toThrow()
    }
  )

  it.each([
    `hostkey ${KEY} #old\nHostCertificate ${CERTIFICATE}\n${ALGORITHMS}`,
    `hostkey ${KEY}\nHostCertificate ${CERTIFICATE} #old\n${ALGORITHMS}`,
  ])(
    "does not mistake a literal suffix for a source comment in a required mapping: %j",
    (effective) => {
      expect(() => {
        assertHostAlgorithms(effective, parseHostCertificate(certificate), {
          policy,
          stagedPath: CERTIFICATE,
        })
      }).toThrow(
        "Effective HostKey, HostCertificate or certificate HostKeyAlgorithms policy conflicts"
      )
    }
  )

  it.each(["/etc/ssh/foreign certificate.pub", "/etc/ssh/foreign #old.pub"])(
    "stages commented source mappings and validates literal effective filenames: %j",
    async (path) => {
      const stagedPath = "/run/paratix/candidate.pub"
      const stagedConfig = "/run/paratix/validation-0"
      const foreignSource = `HostKey "${path}" # key\nHostCertificate "${path}" # certificate\nHostCertificate none # absent\n`
      const ssh = createMockSsh(
        {
          [`sshd -t -f '${stagedConfig}'`]: { code: 0 },
          [`sshd -T -f '${stagedConfig}'`]: {
            stdout: `hostkey ${KEY}\nhostkey ${path}\nHostCertificate ${stagedPath}\nHostCertificate ${path}\n${ALGORITHMS}`,
          },
        },
        {
          allowWrites: [{ options: { mode: "0600" }, remotePath: stagedConfig }],
        }
      )
      await expect(
        validateHostCandidate(ssh, {
          certificate: parseHostCertificate(certificate),
          certificatePath: stagedPath,
          content: `HostKey '${KEY}' # selected\nHostCertificate "${CERTIFICATE}" # managed\n${foreignSource}`,
          directory: "/run/paratix",
          policy,
        })
      ).resolves.toBeUndefined()
      expect(ssh.writeFileCalls).toContainEqual({
        content: `HostKey '${KEY}' # selected\nHostCertificate ${stagedPath}\n${foreignSource}`,
        options: { mode: "0600" },
        remotePath: stagedConfig,
      })
    }
  )

  it.each(["HostCertificate", "HostKey"] as const)(
    "reports empty effective %s through public dry-run and apply without signing",
    async (directive) => {
      vi.spyOn(pending, "hostPendingExists").mockResolvedValue(false)
      const sign = vi.fn()
      const module = hostCertificate({
        principals: policy.principals,
        signer: { caPublicKey: policy.caPublicKey, sign, version: 1 },
      })
      const ssh = targetSsh(`HostKey ${KEY}\n${directive}`)
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
    const ssh = targetSsh(`HostKey ${KEY}`, {
      [`cat '${ROOT}'`]: { stdout: "TrustedUserCAKeys /etc/ssh/ca.pub\n" },
    })
    await expect(module._applyDryRun?.(ssh, {})).resolves.toMatchObject({
      error: { message: "[ssh.hostCertificate] Public state inspection failed" },
      status: "failed",
    })
  })
})
