import { writeFile } from "node:fs/promises"
import { join } from "node:path"
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest"

import type { Module } from "../../src/types.js"

import { podman, shellQuote } from "../../src/index.js"
import {
  createNativePodmanEnvironment,
  type NativePodmanEnvironment,
  nativePodmanTargetConfigured,
  readNativeAuthFile,
} from "./podmanHarness.js"

const shouldRun = nativePodmanTargetConfigured() || process.env.CI === "true"
const TOKEN_LIMIT = 65_535
const AUTH_LIMIT = 8_388_608
const LARGE_ASCII_BYTES = 7_340_048
const MAXIMUM_TOKEN = `${"é".repeat(32_767)}x`
type Source = "controller" | "environment" | "target"
let environment: NativePodmanEnvironment | undefined

function fixture(): NativePodmanEnvironment {
  if (environment === undefined) throw new Error("Native size fixture is not initialized")
  return environment
}
function login(): Module {
  const f = fixture()
  return podman.login({
    authFile: f.authFile,
    helperImage: f.helperImage,
    passwordEnv: "TOKEN",
    registry: f.registry,
    username: f.username,
  })
}
function logout(): Module {
  const f = fixture()
  return podman.logout(f.registry, { authFile: f.authFile, helperImage: f.helperImage })
}
async function loginForSource(source: Source, token: string): Promise<Module> {
  const f = fixture()
  if (source === "environment") return login()
  let path = f.passwordFile
  if (source === "target") await f.write(path, `${token}\n`, "0400")
  else {
    path = join(f.controllerDirectory, `token-${String(Buffer.byteLength(token))}`)
    await writeFile(path, `${token}\r\n`, { mode: 0o400 })
  }
  return podman.login({
    authFile: f.authFile,
    helperImage: f.helperImage,
    passwordFile: path,
    passwordFileLocation: source,
    registry: f.registry,
    username: f.username,
  })
}
async function calls(): Promise<number> {
  const f = fixture()
  const path = `${f.resource}/calls`
  const result = await f.baseSsh.exec(`grep -cx login ${shellQuote(path)} || :`, { silent: true })
  return Number(result.stdout.trim())
}
async function readLargeAuth(): Promise<string> {
  const f = fixture()
  const result = await f.baseSsh.exec(`cat -- ${shellQuote(f.authFile)}`, {
    maxOutputBytes: AUTH_LIMIT + 1,
    silent: true,
  })
  return result.stdout
}
function documentOfSize(bytes: number, auths: Record<string, { auth: string }> = {}): string {
  const empty = JSON.stringify({ auths, extension: "" })
  return JSON.stringify({ auths, extension: "x".repeat(bytes - Buffer.byteLength(empty)) })
}
function ownedEntry(): Record<string, { auth: string }> {
  const f = fixture()
  return { [f.registry]: { auth: Buffer.from(`${f.username}:${f.token}`).toString("base64") } }
}
async function assertClean(): Promise<void> {
  expect(await fixture().leftovers()).toStrictEqual([])
}

describe.skipIf(!shouldRun)("native Podman credential and transaction size boundaries", () => {
  beforeAll(async () => {
    environment = await createNativePodmanEnvironment({ token: MAXIMUM_TOKEN })
  })
  beforeEach(async () => {
    const f = fixture()
    await f.setWrapper("")
    await f.write(f.authFile, "{}")
    await f.write(`${f.resource}/calls`, "")
    f.trace.length = 0
  })
  afterAll(async () => {
    await environment?.cleanup()
  })

  it.each<Source>(["environment", "controller", "target"])(
    "successfully authenticates with exactly 65,535 UTF-8 token bytes from %s",
    async (source) => {
      const f = fixture()
      expect(Buffer.byteLength(f.token)).toBe(TOKEN_LIMIT)
      const module = await loginForSource(source, f.token)
      await expect(module.check(f.ssh, { TOKEN: f.token })).resolves.toBe("needs-apply")
      await expect(module.apply(f.ssh, { TOKEN: f.token })).resolves.toMatchObject({
        status: "changed",
      })
      await expect(module.check(f.ssh, { TOKEN: f.token })).resolves.toBe("ok")
      await expect(module.apply(f.ssh, { TOKEN: f.token })).resolves.toMatchObject({ status: "ok" })
      expect(await calls()).toBe(1)
      expect(f.authenticatedRequests()).toBeGreaterThan(0)
      const auth = JSON.parse(await readNativeAuthFile(f)) as {
        auths: Record<string, { auth: string }>
      }
      expect(auth.auths).toStrictEqual(ownedEntry())
      await assertClean()
    }
  )

  it.each<Source>(["environment", "controller", "target"])(
    "rejects 65,536 UTF-8 token bytes from %s before host authentication or auth mutation",
    async (source) => {
      const f = fixture()
      const token = `${f.token}x`
      expect(Buffer.byteLength(token)).toBe(TOKEN_LIMIT + 1)
      const module = await loginForSource(source, token)
      await expect(module.check(f.ssh, { TOKEN: token })).rejects.toThrow("podman:")
      await expect(module.apply(f.ssh, { TOKEN: token })).resolves.toMatchObject({
        status: "failed",
      })
      expect(await calls()).toBe(0)
      expect(await readNativeAuthFile(f)).toBe("{}")
      await assertClean()
    }
  )

  it("commits a 7,340,048-byte auth file through its larger Base64 state and remains reusable", async () => {
    const f = fixture()
    const original = documentOfSize(LARGE_ASCII_BYTES)
    expect(Buffer.byteLength(original)).toBe(LARGE_ASCII_BYTES)
    const foreign = JSON.parse(original) as { extension: string }
    await f.write(f.authFile, original)
    await expect(login().apply(f.ssh, { TOKEN: f.token })).resolves.toMatchObject({
      status: "changed",
    })
    await expect(login().check(f.ssh, { TOKEN: f.token })).resolves.toBe("ok")
    await expect(login().apply(f.ssh, { TOKEN: f.token })).resolves.toMatchObject({ status: "ok" })
    const published = JSON.parse(await readLargeAuth()) as { extension: string }
    expect(published.extension).toBe(foreign.extension)
    await expect(logout().apply(f.ssh, {})).resolves.toMatchObject({ status: "changed" })
    await expect(logout().check(f.ssh, {})).resolves.toBe("ok")
    const removed = JSON.parse(await readLargeAuth()) as { extension: string }
    expect(removed.extension).toBe(foreign.extension)
    expect(await calls()).toBe(1)
    await assertClean()
  })

  it("refuses Unicode serialization growth beyond 8 MiB before publication and preserves original bytes", async () => {
    const f = fixture()
    const original = JSON.stringify({ extension: "é".repeat(2_097_152) })
    expect(Buffer.byteLength(original)).toBe(4_194_320)
    await f.write(f.authFile, original)
    await expect(login().apply(f.ssh, { TOKEN: f.token })).resolves.toMatchObject({
      status: "failed",
    })
    expect(await readLargeAuth()).toBe(original)
    await expect(login().check(f.ssh, { TOKEN: f.token })).resolves.toBe("needs-apply")
    await expect(logout().apply(f.ssh, {})).resolves.toMatchObject({ status: "ok" })
    expect(await readLargeAuth()).toBe(original)
    expect(await calls()).toBe(1)
    await assertClean()
  })

  it("accepts exactly 8 MiB for a mode-only transaction and subsequent logout", async () => {
    const f = fixture()
    const original = documentOfSize(AUTH_LIMIT, ownedEntry())
    expect(Buffer.byteLength(original)).toBe(AUTH_LIMIT)
    const foreign = JSON.parse(original) as { extension: string }
    await f.write(f.authFile, original, "0644")
    await expect(login().check(f.ssh, { TOKEN: f.token })).resolves.toBe("needs-apply")
    await expect(login().apply(f.ssh, { TOKEN: f.token })).resolves.toMatchObject({
      status: "changed",
    })
    expect(await readLargeAuth()).toBe(original)
    await expect(login().check(f.ssh, { TOKEN: f.token })).resolves.toBe("ok")
    await expect(logout().apply(f.ssh, {})).resolves.toMatchObject({ status: "changed" })
    await expect(logout().check(f.ssh, {})).resolves.toBe("ok")
    const removed = JSON.parse(await readLargeAuth()) as { extension: string }
    expect(removed.extension).toBe(foreign.extension)
    expect(await calls()).toBe(0)
    await assertClean()
  })

  it("refuses an ASCII candidate that would grow beyond the readable auth limit", async () => {
    const f = fixture()
    const original = documentOfSize(AUTH_LIMIT)
    await f.write(f.authFile, original)
    await expect(login().check(f.ssh, { TOKEN: f.token })).resolves.toBe("needs-apply")
    await expect(login().apply(f.ssh, { TOKEN: f.token })).resolves.toMatchObject({
      status: "failed",
    })
    expect(await readLargeAuth()).toBe(original)
    await expect(logout().apply(f.ssh, {})).resolves.toMatchObject({ status: "ok" })
    expect(await readLargeAuth()).toBe(original)
    await assertClean()
  })

  it("rejects an original auth file one byte above 8 MiB without repair", async () => {
    const f = fixture()
    const original = documentOfSize(AUTH_LIMIT + 1)
    await f.write(f.authFile, original)
    await expect(login().check(f.ssh, { TOKEN: f.token })).rejects.toThrow("podman:")
    await expect(login().apply(f.ssh, { TOKEN: f.token })).resolves.toMatchObject({
      status: "failed",
    })
    expect(await readLargeAuth()).toBe(original)
    expect(await calls()).toBe(0)
    await assertClean()
  })
})
