/* oxlint-disable vitest/no-conditional-in-test -- Table-driven cases explicitly select fixture inputs and expected outcomes; every case runs its assertions. */
import { access, chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { inspect } from "node:util"
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest"

import type { FixtureKey } from "./helpers/hostCertificateFixtures.js"

import * as providerProcess from "../src/modules/opSpawnRunner.js"
import { secret } from "../src/modules/secret.js"
import { ssh } from "../src/modules/ssh.js"
import {
  assertSignerCertificate,
  hostCertificatePolicy,
} from "../src/modules/sshHostCertificatePolicy.js"
import * as controllerProcess from "../src/modules/sshSignerProcess.js"
import {
  fixtureKey,
  fixtureRequest,
  CERTIFICATE_NOW as NOW,
} from "./helpers/hostCertificateFixtures.js"

const PASSWORD = "marked-step-adapter-provisioner-password"
const REFERENCE = "op://marked-step-adapter-vault/item/password"
const FLAGS = [
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
let directory: string
let ca: FixtureKey
let publicRoot: string
let trace: string
let behavior: string

type Trace = {
  args: string[]
  credentialMatches: boolean
  credentialMode: number
  directory: string
  directoryMode: number
  home: string
  homeReal: string
  step: string
  subject: string
}

function stepSigner() {
  return ssh.signer.stepCa({
    caPublicKey: ca.publicKey,
    caUrl: "https://isolated-ca.invalid:9443",
    password: secret.provider("1password").deferred(REFERENCE),
    provisioner: "explicit-jwk-fixture",
    root: publicRoot,
  })
}
async function traces(): Promise<Trace[]> {
  const content = await readFile(trace, "utf8")
  return content
    .trim()
    .split("\n")
    .map((line: string): Trace => JSON.parse(line) as Trace)
}

describe("sshSignerAdapters test context", () => {
  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), "paratix-step-adapter-test-"))
    ca = await fixtureKey(directory, "ca", "ed25519")
    publicRoot = join(directory, "test-root.pem")
    await writeFile(publicRoot, "test-local-public-root")
    trace = join(directory, "trace.jsonl")
    behavior = join(directory, "behavior")
    await writeFile(behavior, "sign")
    // Contract-faithful CLI fixture: real subprocess/files/argv and real OpenSSH signing.
    // A live TLS/JWK step-ca is owned by the separate integration suite.
    const script = `#!${process.execPath}
const fs = require("node:fs")
const args = process.argv.slice(2)
if (args[0] === "version") { console.log("Smallstep CLI/0.31.0 (fixture)"); process.exit(0) }
if (args.includes("--help")) { console.log(${JSON.stringify(FLAGS.join("\n"))}); process.exit(0) }
const value = (flag) => args[args.indexOf(flag) + 1]
const passwordFile = value("--provisioner-password-file")
const password = fs.readFileSync(passwordFile, "utf8")
fs.appendFileSync(${JSON.stringify(trace)}, JSON.stringify({args,credentialMatches:password===${JSON.stringify(PASSWORD)},credentialMode:fs.statSync(passwordFile).mode&511,directory:process.cwd(),directoryMode:fs.statSync(process.cwd()).mode&511,home:process.env.HOME,homeReal:fs.realpathSync(process.env.HOME),step:process.env.STEPPATH,subject:fs.readFileSync(args[3],"utf8")})+"\\n")
if (fs.readFileSync(${JSON.stringify(behavior)},"utf8") === "fail") { process.stdout.write(password); process.stderr.write(password); process.exit(4) }
const utc = (value) => value.slice(0,19).replace(/[^0-9]/g, "")+"Z"
const principals = args.flatMap((arg,index) => arg === "--principal" ? [args[index+1]] : [])
const result = require("node:child_process").spawnSync("ssh-keygen", ["-q","-s",${JSON.stringify(ca.path)},"-h","-I",args[2],"-n",principals.join(","),"-V",utc(value("--not-before"))+":"+utc(value("--not-after")),args[3]], {stdio:"pipe"})
process.exit(result.status ?? 1)
`
    await writeFile(join(directory, "step"), script, { mode: 0o700 })
    await chmod(join(directory, "step"), 0o700)
  })
  afterEach(async () => {
    vi.restoreAllMocks()
    vi.unstubAllEnvs()
    await rm(trace, { force: true })
    await writeFile(behavior, "sign")
  })
  afterAll(async () => rm(directory, { force: true, recursive: true }))

  describe("controller signer adapter process contracts", () => {
    it("rejects unsafe constructors and forged credentials before starting a process or loading a provider", () => {
      const process = vi.spyOn(controllerProcess, "signerProcess")
      const provider = vi.spyOn(providerProcess, "spawnWithInput")
      const base = {
        caPublicKey: ca.publicKey,
        caUrl: "https://ca.invalid",
        password: secret.provider("1password").deferred(REFERENCE),
        provisioner: "fixture",
        root: publicRoot,
      }
      for (const caUrl of [
        "http://ca.invalid",
        "https://user:password@ca.invalid",
        "https://ca.invalid?context=personal",
        "https://ca.invalid#context",
        "not a URL",
      ]) {
        expect(() => ssh.signer.stepCa({ ...base, caUrl })).toThrow("HTTPS")
      }
      for (const path of ["relative/path", "/tmp/path\nother", "/tmp/path\u0000other"]) {
        expect(() => ssh.signer.local({ caKey: path, caPublicKey: ca.publicKey })).toThrow("path")
        expect(() => ssh.signer.stepCa({ ...base, root: path })).toThrow("path")
      }
      for (const provisioner of ["", "line\nother", "nul\u0000other"])
        expect(() => ssh.signer.stepCa({ ...base, provisioner })).toThrow("provisioner")
      expect(() =>
        ssh.signer.stepCa({
          ...base,
          // @ts-expect-error Raw strings remain invalid even when callers bypass TypeScript.
          password: REFERENCE,
        })
      ).toThrow("provider-bound")
      expect(() =>
        ssh.signer.local({ caKey: join(directory, "nonexistent-ca"), caPublicKey: ca.publicKey })
      ).not.toThrow()
      expect(provider).not.toHaveBeenCalled()
      expect(process).not.toHaveBeenCalled()
    })

    it.each(["ed25519", "rsa", "ecdsa"])(
      "uses explicit public-key-only Step signing for a %s host and verifies the same certificate contract as local",
      async (algorithm) => {
        vi.stubEnv("PATH", `${directory}:${process.env.PATH ?? ""}`)
        const provider = vi.spyOn(providerProcess, "spawnWithInput").mockResolvedValue(PASSWORD)
        const host = await fixtureKey(
          directory,
          `step-host-${algorithm}`,
          algorithm,
          algorithm === "rsa" ? "2048" : undefined
        )
        const signer = stepSigner()
        const input = fixtureRequest(host.publicKey)
        const certificate = await signer.sign(input)
        const policy = hostCertificatePolicy({
          principals: input.principals,
          renewBefore: "7d",
          signer,
          validity: "14d",
        })
        expect(
          assertSignerCertificate(certificate, {
            now: NOW,
            policy,
            publicKey: host.publicKey,
            request: input,
          }).principals
        ).toStrictEqual(input.principals)
        expect(provider).toHaveBeenCalledExactlyOnceWith("op", ["read", "--", REFERENCE], {
          input: "",
        })
        const calls = await traces()
        expect(calls).toHaveLength(1)
        const call = calls[0]
        expect(call.args.slice(0, 3)).toStrictEqual(["ssh", "certificate", input.requestId])
        expect(call.args[3]).toBe(join(call.home, "host.pub"))
        expect(call.subject.trim()).toBe(host.publicKey.trim().split(/\s+/v).slice(0, 2).join(" "))
        expect(call.subject).not.toContain("PRIVATE KEY")
        for (const flag of ["--host", "--sign", "--force", "--no-agent"])
          expect(call.args).toContain(flag)
        for (const [flag, value] of [
          ["--ca-url", "https://isolated-ca.invalid:9443/"],
          ["--root", publicRoot],
          ["--provisioner", "explicit-jwk-fixture"],
          ["--not-before", new Date(input.validAfter * 1000).toISOString()],
          ["--not-after", new Date(input.validBefore * 1000).toISOString()],
        ])
          expect(call.args[call.args.indexOf(flag) + 1]).toBe(value)
        expect(
          call.args.flatMap((arg, index) => (arg === "--principal" ? [call.args[index + 1]] : []))
        ).toStrictEqual(input.principals)
        expect(call.credentialMatches).toBe(true)
        expect(call.credentialMode).toBe(0o600)
        expect(call.directoryMode).toBe(0o700)
        expect(call.homeReal).toBe(call.directory)
        expect(call.step).toBe(call.home)
        expect(JSON.stringify(call.args)).not.toContain(PASSWORD)
        expect(JSON.stringify(call.args)).not.toContain(REFERENCE)
        expect(JSON.stringify(call.args)).not.toContain(host.path)
        expect(certificate).not.toContain(PASSWORD)
        await expect(access(call.directory)).rejects.toThrow("ENOENT")
        await expect(readFile(join(call.directory, "password"))).rejects.toThrow("ENOENT")
        await expect(readFile(join(call.home, "host.pub"))).rejects.toThrow("ENOENT")
      }
    )

    it("sanitizes failed Step requests including raw stdout/stderr and does not retry an uncertain issuance", async () => {
      vi.stubEnv("PATH", `${directory}:${process.env.PATH ?? ""}`)
      vi.spyOn(providerProcess, "spawnWithInput").mockResolvedValue(PASSWORD)
      await writeFile(behavior, "fail")
      const host = await fixtureKey(directory, "failed-step-host", "ed25519")
      const error = await stepSigner()
        .sign(fixtureRequest(host.publicKey))
        .catch((error: unknown) => error)
      expect(error).toBeInstanceOf(Error)
      expect(inspect(error, { depth: null })).not.toContain(PASSWORD)
      expect(inspect(error, { depth: null })).not.toContain(REFERENCE)
      expect(error).not.toHaveProperty("cause")
      expect(error).toHaveProperty("message", "Deferred signer credential resolution or use failed")
      const calls = await traces()
      expect(calls).toHaveLength(1)
      await expect(readFile(join(calls[0].directory, "password"))).rejects.toThrow("ENOENT")
    })

    it("rejects a local CA mismatch and encrypted keys without prompting or exposing process diagnostics", async () => {
      const host = await fixtureKey(directory, "mismatch-host", "ed25519")
      const wrong = ssh.signer.local({ caKey: host.path, caPublicKey: ca.publicKey })
      await expect(wrong.sign(fixtureRequest(host.publicKey))).rejects.toThrow("does not match")
      const encryptedPath = join(directory, "encrypted-ca")
      const { fixtureCommand } = await import("./helpers/hostCertificateFixtures.js")
      await fixtureCommand("ssh-keygen", [
        "-q",
        "-t",
        "ed25519",
        "-N",
        PASSWORD,
        "-f",
        encryptedPath,
      ])
      const encrypted = ssh.signer.local({
        caKey: encryptedPath,
        caPublicKey: await readFile(`${encryptedPath}.pub`, "utf8"),
      })
      const error = await encrypted
        .sign(fixtureRequest(host.publicKey))
        .catch((error: unknown) => error)
      expect(error).toHaveProperty("message", expect.stringContaining("local CA preflight"))
      expect(inspect(error, { depth: null })).not.toContain(PASSWORD)
      expect(error).not.toHaveProperty("cause")
    })
  })
})
