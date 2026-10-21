/* eslint-disable sonarjs/no-nested-template-literals -- Shell fixture commands interpolate quoted resource paths. */
/* eslint-disable vitest/no-conditional-in-test -- Parameterized credential sources and injected failures require different fixture setup. */
import { chmod, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest"

import type { Module, PodmanLoginOptions } from "../../src/index.js"

import { podman, shellQuote } from "../../src/index.js"
import {
  createNativePodmanEnvironment,
  type NativePodmanEnvironment,
  nativePodmanTargetConfigured,
  readNativeAuthFile,
} from "./podmanHarness.js"

const shouldRun = nativePodmanTargetConfigured() || process.env.CI === "true"
let environment: NativePodmanEnvironment | undefined
function fixture(): NativePodmanEnvironment {
  if (environment === undefined) throw new Error("Native Podman fixture is not initialized")
  return environment
}
function login(options: Partial<PodmanLoginOptions> = {}): Module {
  const f = fixture()
  return podman.login({
    authFile: f.authFile,
    helperImage: f.helperImage,
    passwordEnv: "TOKEN",
    registry: f.registry,
    username: f.username,
    ...options,
  } as PodmanLoginOptions)
}
async function calls(operation: string): Promise<number> {
  const f = fixture()
  const result = await f.baseSsh.exec(
    `grep -cx ${shellQuote(operation)} ${shellQuote(`${f.resource}/calls`)} || :`,
    { silent: true }
  )
  return Number(result.stdout.trim())
}
async function assertClean(): Promise<void> {
  expect(await fixture().leftovers()).toStrictEqual([])
}

describe.skipIf(!shouldRun)("native Podman login/logout integration", () => {
  beforeAll(async () => {
    environment = await createNativePodmanEnvironment()
  })
  beforeEach(async () => {
    const f = fixture()
    await f.setWrapper("")
    f.setRegistryHook()
    await f.write(f.authFile, "{}")
    await f.write(f.passwordFile, f.token, "0400")
    await f.write(`${f.resource}/calls`, "")
    f.trace.length = 0
  })
  afterAll(async () => {
    await environment?.cleanup()
  })

  it("runs the restricted pinned helper in the rootful store without host Python", async () => {
    const f = fixture()
    const hostPythonForbidden = process.env.PARATIX_PODMAN_REQUIRE_NO_HOST_PYTHON === "1"
    expect({ forbidden: hostPythonForbidden, present: f.hostPythonPresent }).not.toMatchObject({
      forbidden: true,
      present: true,
    })
    await expect(login().check(f.ssh, { TOKEN: f.token })).resolves.toBe("needs-apply")
    expect(f.trace[0]?.command).toContain(
      "--pull=never --user 0:0 --userns=host --network=none --read-only"
    )
    expect(f.trace[0]?.command).toContain("--cap-drop=all")
    expect(f.trace[0]?.command).toContain("--log-driver=none")
    await assertClean()
  })

  it.each(["environment", "controller", "target"] as const)(
    "supports %s token, fresh apply rotation, idempotence, and logout",
    async (source) => {
      const f = fixture()
      const controllerToken = join(f.controllerDirectory, `token-${source}`)
      await writeFile(controllerToken, `${f.token}\r\n`, { mode: 0o400 })
      const options = {
        authFile: f.authFile,
        helperImage: f.helperImage,
        registry: f.registry,
        usernameEnv: "USER",
      }
      const module =
        source === "environment"
          ? podman.login({ ...options, passwordEnv: "TOKEN" })
          : podman.login({
              ...options,
              passwordFile: source === "target" ? f.passwordFile : controllerToken,
              passwordFileLocation: source,
            })
      const env = { TOKEN: f.token, USER: f.username }
      await expect(module.check(f.ssh, env)).resolves.toBe("needs-apply")
      await expect(module.apply(f.ssh, env)).resolves.toMatchObject({ status: "changed" })
      expect(await calls("login")).toBe(1)
      await expect(module.check(f.ssh, env)).resolves.toBe("ok")
      await expect(module.apply(f.ssh, env)).resolves.toMatchObject({ status: "ok" })
      expect(await calls("login")).toBe(1)
      // The preceding check must not cache the old token for apply.
      const rotated = `${f.token}-rotated`
      if (source === "controller") {
        await chmod(controllerToken, 0o600)
        await writeFile(controllerToken, `${rotated}\n`)
        await chmod(controllerToken, 0o400)
      } else if (source === "target") await f.write(f.passwordFile, `${rotated}\n`, "0400")
      await expect(module.apply(f.ssh, { ...env, TOKEN: rotated })).resolves.toMatchObject({
        status: "changed",
      })
      await expect(module.check(f.ssh, { ...env, TOKEN: rotated })).resolves.toBe("ok")
      expect(await calls("login")).toBe(2)
      const result = JSON.parse(await readNativeAuthFile(f)) as {
        auths: Record<string, { auth: string }>
      }
      expect(result.auths[f.registry].auth).toBe(
        Buffer.from(`${f.username}:${rotated}`).toString("base64")
      )
      const targetTrace = source === "target" ? f.trace : []
      expect(targetTrace.every((entry) => !String(entry.input).includes(f.token))).toBe(true)
      expect(targetTrace.every((entry) => !entry.command.includes(`cat '${f.passwordFile}'`))).toBe(
        true
      )
      const logout = podman.logout(f.registry, { authFile: f.authFile, helperImage: f.helperImage })
      await expect(logout.check(f.ssh, {})).resolves.toBe("needs-apply")
      await expect(logout.apply(f.ssh, {})).resolves.toMatchObject({ status: "changed" })
      await expect(logout.apply(f.ssh, {})).resolves.toMatchObject({ status: "ok" })
      expect(await calls("logout")).toBe(1)
      await assertClean()
    }
  )

  it("replaces the owned object while preserving foreign JSON and corrects mode without login", async () => {
    const f = fixture()
    const foreign = { auth: "b3RoZXI6Zm9yZWlnbi10b2tlbg==", unknown: { nested: [1, true, null] } }
    const before = {
      auths: {
        [f.registry]: { auth: "dTpvbGQ=", ownedExtension: "replace" },
        "foreign.example": foreign,
      },
      extension: { keep: ["foreign-value", false] },
    }
    await f.write(f.authFile, JSON.stringify(before))
    await expect(login().apply(f.ssh, { TOKEN: f.token })).resolves.toMatchObject({
      status: "changed",
    })
    let auth = JSON.parse(await readNativeAuthFile(f)) as typeof before
    expect(auth.auths["foreign.example"]).toStrictEqual(foreign)
    expect(auth.extension).toStrictEqual(before.extension)
    expect(auth.auths[f.registry]).toStrictEqual({
      auth: Buffer.from(`${f.username}:${f.token}`).toString("base64"),
    })
    await f.baseSsh.exec(
      `chmod 0644 ${shellQuote(f.authFile)}; chmod 0755 ${shellQuote(`${f.resource}/auth`)}`,
      { silent: true }
    )
    await expect(login().check(f.ssh, { TOKEN: f.token })).resolves.toBe("needs-apply")
    await expect(login().apply(f.ssh, { TOKEN: f.token })).resolves.toMatchObject({
      status: "changed",
    })
    await expect(login().apply(f.ssh, { TOKEN: f.token })).resolves.toMatchObject({ status: "ok" })
    expect(await calls("login")).toBe(1)
    const correctedModes = await f.baseSsh.exec(
      `stat -c '%u:%a' ${shellQuote(f.authFile)} ${shellQuote(`${f.resource}/auth`)}`,
      { silent: true }
    )
    expect(correctedModes.stdout.trim()).toBe("0:600\n0:755")
    await podman
      .logout(f.registry, { authFile: f.authFile, helperImage: f.helperImage })
      .apply(f.ssh, {})
    auth = JSON.parse(await readNativeAuthFile(f)) as typeof before
    expect(auth.auths[f.registry]).toBeUndefined()
    expect(auth.auths["foreign.example"]).toStrictEqual(foreign)
    expect(auth.extension).toStrictEqual(before.extension)
    await assertClean()
  })

  it("creates private parents and leaves absent logout untouched without helper image", async () => {
    const f = fixture()
    const authFile = `${f.resource}/new/private/auth.json`
    const logout = podman.logout(f.registry, {
      authFile,
      helperImage: `docker.io/library/python@sha256:${"0".repeat(64)}`,
    })
    await expect(logout.check(f.ssh, {})).resolves.toBe("ok")
    await expect(logout.apply(f.ssh, {})).resolves.toMatchObject({ status: "ok" })
    await expect(login({ authFile }).apply(f.ssh, { TOKEN: f.token })).resolves.toMatchObject({
      status: "changed",
    })
    const createdModes = await f.baseSsh.exec(
      `stat -c '%u:%a' ${shellQuote(`${f.resource}/new`)} ${shellQuote(`${f.resource}/new/private`)} ${shellQuote(authFile)}`,
      { silent: true }
    )
    expect(createdModes.stdout.trim()).toBe("0:700\n0:700\n0:600")
    await assertClean()
  })

  it.each([
    "",
    "{",
    '{"auths":[]}',
    '{"auths":{},"auths":{}}',
    '{"auths":{"foreign.example":{"auth":"!!!"}}}',
    '{"credHelpers":{"example.com":"sentinel"}}',
    '{"auths":{"example.com":{"identitytoken":"opaque"}}}',
  ])("refuses invalid or unsupported auth data without repair: %s", async (content) => {
    const f = fixture()
    const authContent = content.replaceAll("example.com", f.registry)
    await f.write(f.authFile, authContent)
    await expect(login().check(f.ssh, { TOKEN: f.token })).rejects.toThrow("podman:")
    await expect(login().apply(f.ssh, { TOKEN: f.token })).resolves.toMatchObject({
      status: "failed",
    })
    expect(await readNativeAuthFile(f)).toBe(authContent)
    expect(await calls("login")).toBe(0)
    await assertClean()
  })

  it("does not pull a missing image or alter auth state", async () => {
    const f = fixture()
    const module = login({ helperImage: `docker.io/library/python@sha256:${"0".repeat(64)}` })
    await expect(module.check(f.ssh, { TOKEN: f.token })).rejects.toThrow("preload")
    await expect(module.apply(f.ssh, { TOKEN: f.token })).resolves.toMatchObject({
      status: "failed",
    })
    expect(await calls("pull")).toBe(0)
    expect(await readNativeAuthFile(f)).toBe("{}")
  })

  it("keeps original bytes after registry failure and detects concurrent mutation without rollback", async () => {
    const f = fixture()
    const original = '{"extension":"preserve bytes"}\n'
    await f.write(f.authFile, original)
    await expect(
      login().apply(f.ssh, { TOKEN: "synthetic-rejected-token" })
    ).resolves.toMatchObject({ status: "failed" })
    expect(await readNativeAuthFile(f)).toBe(original)
    const foreignWrite = '{"extension":"concurrent writer"}'
    f.setRegistryHook(async () => {
      await f.write(f.authFile, foreignWrite)
    })
    const result = await login().apply(f.ssh, { TOKEN: f.token })
    expect(result).toMatchObject({ status: "failed" })
    expect(result.error?.message).toContain("concurrent")
    expect(await readNativeAuthFile(f)).toBe(foreignWrite)
    await assertClean()
  })

  it.each(["index.docker.io", "registry-1.docker.io", "https://index.docker.io/v1/"])(
    "refuses existing Docker Hub alias %s before host authentication or mutation",
    async (alias) => {
      const f = fixture()
      const original = JSON.stringify({ auths: { [alias]: { auth: "dTpvbGQ=" } } })
      await f.write(f.authFile, original)
      const module = podman.login({
        authFile: f.authFile,
        helperImage: f.helperImage,
        passwordEnv: "TOKEN",
        registry: "docker.io",
        username: f.username,
      })
      await expect(module.check(f.ssh, { TOKEN: f.token })).rejects.toThrow("before publication")
      await expect(module.apply(f.ssh, { TOKEN: f.token })).resolves.toMatchObject({
        status: "failed",
      })
      expect(await readNativeAuthFile(f)).toBe(original)
      expect(await calls("login")).toBe(0)
      await assertClean()
    }
  )
})
