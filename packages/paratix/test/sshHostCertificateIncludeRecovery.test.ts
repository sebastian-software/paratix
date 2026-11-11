import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest"

import type { SshdConfigTransaction } from "../src/modules/sshd.js"
import type { PendingState } from "../src/modules/sshHostCertificatePending.js"
import type { HostCertificatePolicy } from "../src/modules/sshHostCertificatePolicy.js"

import { contentHash } from "../src/modules/sshCertificateFiles.js"
import * as pending from "../src/modules/sshHostCertificatePending.js"
import { parsePending } from "../src/modules/sshHostCertificatePendingSchema.js"
import {
  hostCertificatePolicy,
  parseHostCertificate,
} from "../src/modules/sshHostCertificatePolicy.js"
import {
  commitHostPending,
  recoverHostPending,
  restoreHostPending,
} from "../src/modules/sshHostCertificateRecovery.js"
import {
  validateHostCandidate,
  validateHostRollback,
} from "../src/modules/sshHostCertificateStaging.js"
import { HOST_SSHD_CONFIG, inspectHostTarget } from "../src/modules/sshHostCertificateTarget.js"
import {
  CERTIFICATE_NOW,
  fixtureCertificate,
  fixtureKey,
  fixtureRequest,
} from "./helpers/hostCertificateFixtures.js"
import { createMockSsh } from "./helpers/mockSsh.js"

const PENDING_ID = "11111111-1111-4111-8111-111111111111"
const STAGING = `/var/lib/paratix/host-certificate-state-${PENDING_ID}`
const CERTIFICATE_WORD = "ssh_host_ed25519_key-cert.pub"
const CERTIFICATE_PATH = `/etc/ssh/${CERTIFICATE_WORD}`
const HOST_KEY_PATH = "/etc/ssh/ssh_host_ed25519_key"
const ORIGINAL_CONFIG = `HostKey ${HOST_KEY_PATH}\nInclude missing.conf # ${CERTIFICATE_WORD}\n`
let directory: string
let certificate: string
let publicKey: string
let policy: HostCertificatePolicy

function expandCommand(pattern: string): string {
  return `for paratix_include in ${pattern}; do if [ -e "$paratix_include" ] || [ -L "$paratix_include" ]; then printf '%s\\n' "$paratix_include"; fi; done`
}

function stagingSsh(content = ORIGINAL_CONFIG) {
  return createMockSsh(
    {
      [`[ -e '${CERTIFICATE_PATH}' ]`]: { code: 1 },
      [`cat '${HOST_SSHD_CONFIG}'`]: { stdout: content },
      [`ssh-keygen -y -P '' -f '${HOST_KEY_PATH}' </dev/null`]: { stdout: publicKey },
      "sshd -t": { code: 0 },
    },
    {
      allowWrites: [
        {
          options: { mode: "0600" },
          remotePath:
            /^\/var\/lib\/paratix\/host-certificate-state-[a-f0-9\-]{36}\/validation-\d+$/v,
        },
      ],
      responseStubs: [
        { command: /^\[ -L /v, result: { code: 1 } },
        { command: /^\[ -[edf] /v, result: { code: 0 } },
        { command: /^stat -c '%a %u %g' -- /v, result: { stdout: "600 0 0" } },
        { command: /^stat -c '%h' -- /v, result: { stdout: "1" } },
        { command: /^sha256sum /v, result: { stdout: "hash  file" } },
        { command: /^for paratix_include in /v, result: { stdout: "" } },
        { command: /^sshd -t -f /v, result: { code: 0 } },
        { command: /^sshd -T -f /v, result: { stdout: `hostkey ${HOST_KEY_PATH}\n` } },
      ],
    }
  )
}

function recoveryBoundary(phase: "prepared" | "rollback", originalConfig = ORIGINAL_CONFIG) {
  const connection = stagingSsh()
  const candidateConfig = `HostCertificate ${CERTIFICATE_PATH}\n${originalConfig}`
  const originalState = { hash: contentHash(originalConfig), metadata: "600 0 0" }
  const state: PendingState = {
    hash: contentHash("Pending fixture"),
    manifest: {
      dependencies: [],
      files: [
        {
          candidate: { hash: contentHash(certificate), metadata: "644 0 0" },
          original: null,
          path: CERTIFICATE_PATH,
          role: "certificate",
        },
        {
          candidate: { hash: contentHash(candidateConfig), metadata: "600 0 0" },
          original: originalState,
          path: HOST_SSHD_CONFIG,
          role: "config",
        },
      ],
      hostKeyState: { hash: contentHash("host key fixture"), metadata: "600 0 0" },
      id: PENDING_ID,
      phase,
      policy,
      publicKey,
      version: 1,
    },
  }
  state.manifest = parsePending(state.manifest)
  state.hash = contentHash(JSON.stringify(state.manifest))
  const live = new Map([
    [CERTIFICATE_PATH, certificate],
    [HOST_SSHD_CONFIG, candidateConfig],
  ])
  const snapshots = new Map([
    [pending.pendingSidecar(state.manifest, "certificate", "candidate"), certificate],
    [pending.pendingSidecar(state.manifest, "config", "candidate"), candidateConfig],
    [pending.pendingSidecar(state.manifest, "config", "original"), originalConfig],
  ])
  vi.spyOn(connection, "readFile").mockImplementation(async (path) => {
    await Promise.resolve()
    const value = snapshots.get(path) ?? live.get(path)
    if (value === undefined) throw new Error(`Missing fixture file: ${path}`)
    return value
  })
  const exec = connection.exec
  vi.spyOn(connection, "exec").mockImplementation(async (command, options) => {
    if (command === expandCommand(`'${CERTIFICATE_PATH}'`))
      return { code: 0, stderr: "", stdout: live.has(CERTIFICATE_PATH) ? CERTIFICATE_PATH : "" }
    if (command === expandCommand("'/etc/ssh/unrelated'"))
      return { code: 0, stderr: "", stdout: "/etc/ssh/unrelated" }
    return exec(command, options)
  })
  const transaction: SshdConfigTransaction = {
    connection,
    preparePrivilegeSeparation: vi.fn(),
    readEffective: vi.fn(),
    readEffectiveOutput: vi.fn(),
    reload: vi.fn(),
    reloadOnly: vi.fn(),
    requireReloadOnly: vi.fn(),
    restoreReload: vi.fn(),
    validate: vi.fn(),
  }
  vi.spyOn(pending, "verifyHostPending").mockResolvedValue()
  vi.spyOn(pending, "readHostPending").mockResolvedValue(state)
  const transition = vi
    .spyOn(pending, "transitionHostPending")
    .mockImplementation(async (_ssh, current, nextPhase) => {
      await Promise.resolve()
      return {
        ...current,
        manifest: { ...current.manifest, phase: nextPhase },
      }
    })
  const publish = vi
    .spyOn(pending, "publishHostFile")
    .mockImplementation(async (_ssh, current, input) => {
      await Promise.resolve()
      const content = snapshots.get(
        pending.pendingSidecar(current.manifest, input.file.role, input.kind)
      )
      if (content === undefined) live.delete(input.file.path)
      else live.set(input.file.path, content)
    })
  const cleanup = vi.spyOn(pending, "cleanupHostPending").mockResolvedValue()
  return { cleanup, connection, live, publish, snapshots, state, transaction, transition }
}

describe("host certificate Include publication and recovery", () => {
  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), "paratix-include-recovery-"))
    const ca = await fixtureKey(directory, "ca", "ed25519")
    const host = await fixtureKey(directory, "host", "ed25519")
    publicKey = host.publicKey.trim().split(/\s+/v).slice(0, 2).join(" ")
    certificate = await fixtureCertificate(directory, ca, fixtureRequest(publicKey))
    policy = hostCertificatePolicy({
      principals: ["host.test", "192.0.2.1"],
      signer: { caPublicKey: ca.publicKey, sign: vi.fn(), version: 1 },
      validity: "14d",
    })
  })
  afterEach(() => vi.restoreAllMocks())
  afterAll(async () => rm(directory, { force: true, recursive: true }))

  it("passes the planned certificate path during target inspection without a HostCertificate directive", async () => {
    const connection = stagingSsh()
    await expect(inspectHostTarget(connection, policy)).rejects.toThrow(
      `comment word ${CERTIFICATE_WORD}`
    )
    expect(connection.calls).not.toContain("sshd -T")
    expect(connection.writeFileCalls).toStrictEqual([])
  })

  it("passes the planned certificate path when staging without a HostCertificate directive", async () => {
    const connection = stagingSsh()
    await expect(
      validateHostCandidate(connection, {
        certificate: parseHostCertificate(certificate),
        certificatePath: `${STAGING}/candidate-certificate`,
        content: ORIGINAL_CONFIG,
        directory: STAGING,
        policy,
      })
    ).rejects.toThrow(`comment word ${CERTIFICATE_WORD}`)
    expect(connection.writeFileCalls).toStrictEqual([])
  })

  it("rolls back a failed legacy Pending candidate despite its currently published certificate", async () => {
    vi.spyOn(Date, "now").mockReturnValue(CERTIFICATE_NOW * 1000)
    const boundary = recoveryBoundary("prepared")
    await expect(commitHostPending(boundary.transaction, boundary.state)).rejects.toThrow(
      "previous state restored and reloaded"
    )
    expect(boundary.live.has(CERTIFICATE_PATH)).toBe(false)
    expect(boundary.live.get(HOST_SSHD_CONFIG)).toBe(ORIGINAL_CONFIG)
    expect(boundary.publish.mock.calls.map((call) => call[2].kind)).toStrictEqual([
      "original",
      "original",
    ])
    expect(boundary.transaction.reloadOnly).toHaveBeenCalledExactlyOnceWith()
    expect(boundary.cleanup).toHaveBeenCalledOnce()
    expect(boundary.transition.mock.calls.map((call) => call[2])).toStrictEqual([
      "rollback",
      "complete-old",
    ])
  })

  it("recovers retained rollback Pending evidence against the restored absent certificate", async () => {
    const boundary = recoveryBoundary("rollback")
    await expect(recoverHostPending(boundary.transaction, policy)).resolves.toBe("restored")
    expect(boundary.live.has(CERTIFICATE_PATH)).toBe(false)
    expect(boundary.live.get(HOST_SSHD_CONFIG)).toBe(ORIGINAL_CONFIG)
    expect(boundary.connection.writeFileCalls.at(-1)?.content).toContain("# Empty Include")
    expect(boundary.transaction.reloadOnly).toHaveBeenCalledExactlyOnceWith()
    expect(boundary.cleanup).toHaveBeenCalledOnce()
  })

  it("retains Pending without restoring or reloading when an unrelated live comment target is unsafe", async () => {
    const boundary = recoveryBoundary(
      "rollback",
      `${ORIGINAL_CONFIG}Include missing.conf # unrelated\n`
    )
    await expect(recoverHostPending(boundary.transaction, policy)).rejects.toThrow(
      "comment word unrelated"
    )
    expect(boundary.publish).not.toHaveBeenCalled()
    expect(boundary.transaction.reloadOnly).not.toHaveBeenCalled()
    expect(boundary.cleanup).not.toHaveBeenCalled()
    expect(boundary.live.has(CERTIFICATE_PATH)).toBe(true)
  })

  it("does not treat a restored existing certificate as absent", async () => {
    const connection = stagingSsh()
    await expect(
      validateHostRollback(connection, {
        certificateContent: certificate,
        certificatePath: `${STAGING}/original-certificate`,
        content: ORIGINAL_CONFIG,
        directory: STAGING,
        policy,
      })
    ).rejects.toThrow(`comment word ${CERTIFICATE_WORD}`)
    expect(connection.writeFileCalls).toStrictEqual([])
  })

  it("validates a restored HostCertificate using the immutable original snapshot", async () => {
    const connection = stagingSsh()
    await validateHostRollback(connection, {
      certificateContent: certificate,
      certificatePath: `${STAGING}/original-certificate`,
      content: `HostCertificate ${CERTIFICATE_PATH}\nInclude missing.conf # ordinary note\n`,
      directory: STAGING,
      policy,
    })
    expect(connection.writeFileCalls.at(-1)?.content).toContain(
      `HostCertificate ${STAGING}/original-certificate`
    )
    expect(connection.calls.filter((command) => /^sshd -[tT] -f /v.test(command))).toHaveLength(2)
  })

  it("reads and restores an existing original certificate from its Pending sidecar", async () => {
    const boundary = recoveryBoundary(
      "rollback",
      `HostCertificate ${CERTIFICATE_PATH}\nInclude missing.conf # ordinary note\n`
    )
    const originalCertificate = `${certificate.trim()} original\n`
    boundary.state.manifest.files[0].original = {
      hash: contentHash(originalCertificate),
      metadata: "644 0 0",
    }
    const originalPath = pending.pendingSidecar(boundary.state.manifest, "certificate", "original")
    boundary.snapshots.set(originalPath, originalCertificate)
    await restoreHostPending(boundary.transaction, boundary.state)
    expect(boundary.live.get(CERTIFICATE_PATH)).toBe(originalCertificate)
    expect(boundary.connection.writeFileCalls.at(-1)?.content).toContain(
      `HostCertificate ${originalPath}`
    )
    expect(boundary.transaction.reloadOnly).toHaveBeenCalledExactlyOnceWith()
    expect(boundary.cleanup).toHaveBeenCalledOnce()
  })
})
