import { execFile } from "node:child_process"
import { access, mkdtemp, readFile, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest"

import type { HostCertificateRequest } from "../src/modules/sshHostCertificateTypes.js"

import * as providerProcess from "../src/modules/opSpawnRunner.js"
import { secret } from "../src/modules/secret.js"
import { ssh } from "../src/modules/ssh.js"
import { checkOpenSshCapabilities } from "../src/modules/sshSignerCapabilities.js"
import * as controllerProcess from "../src/modules/sshSignerProcess.js"

const STEP_FLAGS = [
  "--ca-url",
  "--force",
  "--host",
  "--no-agent",
  "--not-after",
  "--not-before",
  "--principal",
  "--provisioner",
  "--provisioner-password-file",
  "--root",
  "--sign",
]
const MARKER = "private-diagnostic-sentinel"
const realProcess = controllerProcess.signerProcess
let directory: string
let caPublicKey: string
let publicKey: string

async function generateKey(path: string, algorithm = "ed25519"): Promise<void> {
  return new Promise((resolveExit, reject) => {
    execFile("ssh-keygen", ["-q", "-t", algorithm, "-N", "", "-f", path], (error) => {
      if (error === null) resolveExit()
      else reject(new Error("Capability fixture key generation failed", { cause: error }))
    })
  })
}

function request(): HostCertificateRequest {
  const validAfter = Math.floor(Date.now() / 1000)
  return {
    principals: ["host.test"],
    publicKey,
    requestId: "capability-test",
    signal: new AbortController().signal,
    validAfter,
    validBefore: validAfter + 86_400,
    version: 1,
  }
}
function stepSigner() {
  return ssh.signer.stepCa({
    caPublicKey,
    caUrl: "https://ca.invalid",
    password: secret.provider("1password").deferred("op://capability-test/item/password"),
    provisioner: "test-provisioner",
    root: join(directory, "public-root.pem"),
  })
}

function stepTool(
  options: { flags?: string[]; onHelp?: () => void; order?: string[]; version?: string } = {}
) {
  return vi
    .spyOn(controllerProcess, "signerProcess")
    .mockImplementation(async (command, args, processOptions) => {
      if (command !== "step") return realProcess(command, args, processOptions)
      if (args[0] === "version") {
        options.order?.push("version")
        return options.version ?? "Smallstep CLI/0.31.0 (linux/arm64)\n"
      }
      if (args.includes("--help")) {
        options.order?.push("help")
        options.onHelp?.()
        return (options.flags ?? STEP_FLAGS).join("\n")
      }
      options.order?.push("sign")
      throw new Error(MARKER)
    })
}

async function signProbeWithDifferentBounds(
  command: string,
  args: string[],
  options: Parameters<typeof realProcess>[2]
): Promise<string> {
  const changed = [...args]
  if (args.includes("-s")) changed[changed.indexOf("-V") + 1] = "20010203040506Z:20010203050508Z"
  return realProcess(command, changed, options)
}

describe("controller signer capability boundary", () => {
  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), "paratix-signer-capabilities-test-"))
    await generateKey(join(directory, "key"))
    publicKey = await readFile(join(directory, "key.pub"), "utf8")
    caPublicKey = publicKey
  })
  afterEach(() => {
    vi.restoreAllMocks()
  })
  afterAll(async () => {
    await rm(directory, { force: true, recursive: true })
  })

  it("does not start preflight tools or providers during construction, check or dry-run", async () => {
    const process = vi.spyOn(controllerProcess, "signerProcess")
    const provider = vi.spyOn(providerProcess, "spawnWithInput")
    const module = ssh.hostCertificate({ principals: ["host.test"], signer: stepSigner() })
    expect(await module.check(null, {})).toBe("needs-apply")
    const dryRun = await module._applyDryRun?.(null, {})
    expect(dryRun?.status).toBe("failed")
    expect(process).not.toHaveBeenCalled()
    expect(provider).not.toHaveBeenCalled()
  })

  it("proves actual OpenSSH signing, exact UTC seconds, principals and public-key derivation", async () => {
    await expect(
      controllerProcess.withSignerDirectory(async (temporary) =>
        checkOpenSshCapabilities(temporary, request(), caPublicKey)
      )
    ).resolves.toBeUndefined()
  })

  it.each(["rsa", "ecdsa"])(
    "proves OpenSSH facilities with the configured %s CA algorithm",
    async (algorithm) => {
      const path = join(directory, `probe-${algorithm}`)
      await generateKey(path, algorithm)
      const ca = await readFile(`${path}.pub`, "utf8")
      await expect(
        controllerProcess.withSignerDirectory(async (temporary) =>
          checkOpenSshCapabilities(temporary, request(), ca)
        )
      ).resolves.toBeUndefined()
    }
  )

  it("rejects a validly signed probe with different time bounds before reading the configured CA", async () => {
    const process = vi
      .spyOn(controllerProcess, "signerProcess")
      .mockImplementation(signProbeWithDifferentBounds)
    const caKey = join(directory, "must-not-be-read")
    const signer = ssh.signer.local({ caKey, caPublicKey })
    await expect(signer.sign(request())).rejects.toThrow("absolute UTC facilities")
    expect(process.mock.calls.some(([, args]) => args.includes(caKey))).toBe(false)
  })

  it("fails an unavailable or unsupported OpenSSH tool before any Step or provider invocation", async () => {
    const process = vi
      .spyOn(controllerProcess, "signerProcess")
      .mockRejectedValue(new Error(MARKER))
    const provider = vi.spyOn(providerProcess, "spawnWithInput")
    const operation = stepSigner().sign(request())
    await expect(operation).rejects.toThrow("ssh-keygen lacks required")
    await expect(operation).rejects.not.toThrow(MARKER)
    expect(process.mock.calls.every(([command]) => command === "ssh-keygen")).toBe(true)
    expect(provider).not.toHaveBeenCalled()
    const temporary = process.mock.calls[0]?.[2].directory
    expect(temporary).toMatch(/paratix-host-signer-/v)
    await expect(access(temporary)).rejects.toMatchObject({ code: "ENOENT" })
  })

  it.each(STEP_FLAGS)("rejects Step without %s before credential resolution", async (missing) => {
    stepTool({ flags: STEP_FLAGS.filter((flag) => flag !== missing) })
    const provider = vi.spyOn(providerProcess, "spawnWithInput")
    await expect(stepSigner().sign(request())).rejects.toThrow(`options: ${missing}`)
    expect(provider).not.toHaveBeenCalled()
  })

  it("rejects an unidentified Step version without exposing its raw output", async () => {
    const process = stepTool({ version: MARKER })
    const provider = vi.spyOn(providerProcess, "spawnWithInput")
    const operation = stepSigner().sign(request())
    await expect(operation).rejects.toThrow("version could not be identified")
    await expect(operation).rejects.not.toThrow(MARKER)
    expect(process.mock.calls.filter(([command]) => command === "step")).toHaveLength(1)
    expect(provider).not.toHaveBeenCalled()
  })

  it("honors cancellation after public preflight before resolving a credential", async () => {
    const controller = new AbortController()
    stepTool({
      onHelp() {
        controller.abort()
      },
    })
    const provider = vi.spyOn(providerProcess, "spawnWithInput")
    await expect(stepSigner().sign({ ...request(), signal: controller.signal })).rejects.toThrow(
      /abort/iv
    )
    expect(provider).not.toHaveBeenCalled()
  })

  it("allows a capable Step build and only then resolves a credential and attempts signing", async () => {
    const order: string[] = []
    stepTool({ order })
    const provider = vi.spyOn(providerProcess, "spawnWithInput").mockImplementation(async () => {
      order.push("credential")
      return new Promise<string>((resolve) => {
        resolve(MARKER)
      })
    })
    const operation = stepSigner().sign(request())
    await expect(operation).rejects.toThrow("Deferred signer credential resolution or use failed")
    await expect(operation).rejects.not.toThrow(MARKER)
    expect(order).toStrictEqual(["version", "help", "credential", "sign"])
    expect(provider).toHaveBeenCalledExactlyOnceWith(
      "op",
      ["read", "--", "op://capability-test/item/password"],
      { input: "" }
    )
  })
})
